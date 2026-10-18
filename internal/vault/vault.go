// Package vault retrieves BMC credentials. The production implementation talks
// to the CyberArk Central Credential Provider (CCP) REST API with a client
// certificate. Secrets live only in memory (see Store), are never logged and
// are cached per CyberArk account, so the deployment can use one shared
// account for every BMC or one account per BMC.
package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Credential is a username/password pair for a BMC. Version changes whenever
// the cached password changes (rotation), so callers can tell whether a
// refetch brought a new secret without ever comparing passwords themselves.
type Credential struct {
	Username string
	Password string
	Version  uint64
}

// Report summarizes a Refresh call. It never carries secret values.
type Report struct {
	Requested int        `json:"requested"`
	Fetched   int        `json:"fetched"`
	Changed   int        `json:"changed"` // fetched and the password differs from the cached one (rotation)
	Skipped   int        `json:"skipped"` // not due yet
	Failed    int        `json:"failed"`
	Errors    []RefError `json:"errors,omitempty"`
}

// RefError is one failed account in a Report.
type RefError struct {
	Ref string `json:"ref"`
	Err string `json:"error"`
}

// Stats is a point-in-time view of the cache.
type Stats struct {
	Entries int
}

// Provider hands out BMC credentials per account.
type Provider interface {
	// Resolve maps an inventory secret_ref onto an account according to the
	// configured mode (shared, per_asset or auto).
	Resolve(secretRef string) (Ref, error)
	// Get returns the credential for ref, from cache when fresh.
	Get(ctx context.Context, ref Ref) (Credential, error)
	// Invalidate marks the cached secret as rejected by a BMC. version is the
	// Credential.Version that was rejected; if the cache already holds a newer
	// one, or the secret was fetched very recently, nothing happens. Callers
	// re-Get afterwards and retry only if Version changed.
	Invalidate(ref Ref, version uint64)
	// Refresh re-reads accounts from the vault. With force it refetches all of
	// refs, otherwise only those missing or close to expiry.
	Refresh(ctx context.Context, refs []Ref, force bool) Report
	Stats() Stats
	Name() string
}

// Fetcher reads one account from the backing vault, without caching.
type Fetcher interface {
	Fetch(ctx context.Context, ref Ref) (Credential, error)
	Name() string
}

// ---------------------------------------------------------------- CyberArk

// CyberArkConfig mirrors the local YAML section.
type CyberArkConfig struct {
	URL        string
	AppID      string
	Safe       string // default account (shared mode) or default Safe for object-only refs
	Object     string
	ClientCert string
	ClientKey  string
	CAFile     string

	Mode          Mode
	CacheTTL      time.Duration
	StaleMax      time.Duration
	RefreshAhead  float64
	MaxConcurrent int

	Store Store // nil → PlainStore
	Hooks Hooks
}

type ccp struct {
	cfg    CyberArkConfig
	client *http.Client
}

// NewCyberArk builds a CCP client authenticated by client certificate, wrapped
// in the per-account secret cache.
func NewCyberArk(cfg CyberArkConfig) (Provider, error) {
	if cfg.Mode == "" {
		cfg.Mode = ModeAuto
	}
	if cfg.URL == "" || cfg.AppID == "" {
		return nil, errors.New("cyberark: url and app_id are required")
	}
	if cfg.Mode != ModeShared && cfg.Mode != ModePerAsset && cfg.Mode != ModeAuto {
		return nil, fmt.Errorf("cyberark: unknown mode %q (shared, per_asset or auto)", cfg.Mode)
	}
	if cfg.Mode != ModePerAsset && (cfg.Safe == "" || cfg.Object == "") {
		return nil, fmt.Errorf("cyberark: safe and object are required in %s mode", cfg.Mode)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.ClientCert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("cyberark: load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("cyberark: read ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("cyberark: ca file holds no certificate")
		}
		tlsCfg.RootCAs = pool
	}
	f := &ccp{
		cfg: cfg,
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}
	return NewCache(f, CacheConfig{
		Mode:          cfg.Mode,
		Default:       Ref{Safe: cfg.Safe, Object: cfg.Object},
		TTL:           cfg.CacheTTL,
		StaleMax:      cfg.StaleMax,
		RefreshAhead:  cfg.RefreshAhead,
		MaxConcurrent: cfg.MaxConcurrent,
		Store:         cfg.Store,
		Hooks:         cfg.Hooks,
	}), nil
}

func (c *ccp) Name() string { return "cyberark-ccp" }

// Fetch performs GET {url}?AppID=&Safe=&Object= as documented for the CCP
// AIMWebService. The response carries Content (password) and UserName.
func (c *ccp) Fetch(ctx context.Context, ref Ref) (Credential, error) {
	if ref.Safe == "" || ref.Object == "" {
		return Credential{}, fmt.Errorf("cyberark: incomplete account reference %q", ref.String())
	}
	q := url.Values{}
	q.Set("AppID", c.cfg.AppID)
	q.Set("Safe", ref.Safe)
	q.Set("Object", ref.Object)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.URL+"?"+q.Encode(), nil)
	if err != nil {
		return Credential{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return Credential{}, fmt.Errorf("cyberark: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Never include the body: CCP error bodies can echo request details.
		return Credential{}, fmt.Errorf("cyberark: HTTP %d", resp.StatusCode)
	}
	var body struct {
		Content  string `json:"Content"`
		UserName string `json:"UserName"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Credential{}, fmt.Errorf("cyberark: decode: %w", err)
	}
	if body.Content == "" || body.UserName == "" {
		return Credential{}, errors.New("cyberark: empty credential in response")
	}
	return Credential{Username: body.UserName, Password: body.Content}, nil
}

// ---------------------------------------------------------------- Env (lab)

type envProvider struct{ userEnv, passEnv string }

// NewEnv reads the credential from two environment variables. Lab only; every
// BMC shares it and secret_ref is ignored.
func NewEnv(userEnv, passEnv string) Provider {
	return &envProvider{userEnv: userEnv, passEnv: passEnv}
}

func (e *envProvider) Name() string                { return "env" }
func (e *envProvider) Resolve(string) (Ref, error) { return Ref{}, nil }
func (e *envProvider) Invalidate(Ref, uint64)      {}
func (e *envProvider) Stats() Stats                { return Stats{} }
func (e *envProvider) Refresh(_ context.Context, refs []Ref, _ bool) Report {
	return Report{Requested: len(refs), Skipped: len(refs)}
}
func (e *envProvider) Get(context.Context, Ref) (Credential, error) {
	u, p := os.Getenv(e.userEnv), os.Getenv(e.passEnv)
	if u == "" || p == "" {
		return Credential{}, fmt.Errorf("env provider: %s or %s is empty", e.userEnv, e.passEnv)
	}
	return Credential{Username: u, Password: p}, nil
}
