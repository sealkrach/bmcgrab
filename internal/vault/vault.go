// Package vault retrieves the BMC credential. The production implementation
// talks to the CyberArk Central Credential Provider (CCP) REST API with a
// client certificate. The secret lives only in memory, is never logged and is
// refreshed on a TTL.
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
	"sync"
	"time"
)

// Credential is a username/password pair for the BMCs.
type Credential struct {
	Username string
	Password string
}

// Provider returns the current BMC credential.
type Provider interface {
	Get(ctx context.Context) (Credential, error)
	// Invalidate drops the cached secret (called after an auth failure so the
	// next cycle fetches a fresh one, e.g. after rotation).
	Invalidate()
	Name() string
}

// ---------------------------------------------------------------- CyberArk

// CyberArkConfig mirrors the local YAML section.
type CyberArkConfig struct {
	URL        string
	AppID      string
	Safe       string
	Object     string
	ClientCert string
	ClientKey  string
	CAFile     string
	CacheTTL   time.Duration
}

type cyberark struct {
	cfg    CyberArkConfig
	client *http.Client

	mu      sync.Mutex
	cred    Credential
	fetched time.Time
}

// NewCyberArk builds a CCP client authenticated by client certificate.
func NewCyberArk(cfg CyberArkConfig) (Provider, error) {
	if cfg.URL == "" || cfg.AppID == "" || cfg.Safe == "" || cfg.Object == "" {
		return nil, errors.New("cyberark: url, app_id, safe and object are required")
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
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = time.Hour
	}
	return &cyberark{
		cfg: cfg,
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

func (c *cyberark) Name() string { return "cyberark-ccp" }

func (c *cyberark) Get(ctx context.Context) (Credential, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cred.Password != "" && time.Since(c.fetched) < c.cfg.CacheTTL {
		return c.cred, nil
	}
	cred, err := c.fetch(ctx)
	if err != nil {
		// Keep serving the stale secret if we have one; it is better than
		// stopping collection because the CCP is briefly unreachable.
		if c.cred.Password != "" {
			return c.cred, nil
		}
		return Credential{}, err
	}
	c.cred, c.fetched = cred, time.Now()
	return cred, nil
}

func (c *cyberark) Invalidate() {
	c.mu.Lock()
	c.cred = Credential{}
	c.fetched = time.Time{}
	c.mu.Unlock()
}

// fetch performs GET {url}?AppID=&Safe=&Object= as documented for the CCP
// AIMWebService. The response carries Content (password) and UserName.
func (c *cyberark) fetch(ctx context.Context) (Credential, error) {
	q := url.Values{}
	q.Set("AppID", c.cfg.AppID)
	q.Set("Safe", c.cfg.Safe)
	q.Set("Object", c.cfg.Object)
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

// NewEnv reads the credential from two environment variables. Lab only.
func NewEnv(userEnv, passEnv string) Provider {
	return &envProvider{userEnv: userEnv, passEnv: passEnv}
}

func (e *envProvider) Name() string { return "env" }
func (e *envProvider) Invalidate()  {}
func (e *envProvider) Get(context.Context) (Credential, error) {
	u, p := os.Getenv(e.userEnv), os.Getenv(e.passEnv)
	if u == "" || p == "" {
		return Credential{}, fmt.Errorf("env provider: %s or %s is empty", e.userEnv, e.passEnv)
	}
	return Credential{Username: u, Password: p}, nil
}
