// Package inventory loads the list of servers from an external source. bmcgrab
// never owns the inventory: it consumes SQL, REST or CSV and keeps only a
// local cache of the last list for resilience.
package inventory

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sealkrach/bmcgrab/internal/config"
	"github.com/sealkrach/bmcgrab/internal/model"
)

// Provider returns the servers of one region.
type Provider interface {
	List(ctx context.Context, region string) ([]model.Server, error)
	Name() string
}

// New builds the provider named by the central config.
func New(c *config.Central) (Provider, error) {
	switch c.Inventory.Type {
	case "sql":
		return newSQL(c.Inventory.SQL.DSN, os.Getenv(c.Inventory.SQL.PasswordEnv), c.Inventory.SQL.Query)
	case "rest":
		return newREST(c.Inventory.REST.URL, c.Inventory.REST.JSONPath, os.Getenv(c.Inventory.REST.TokenEnv)), nil
	case "csv":
		return &csvProvider{path: c.Inventory.CSV.Path}, nil
	}
	return nil, fmt.Errorf("inventory: unknown type %q", c.Inventory.Type)
}

// ------------------------------------------------------------------- cached

// Cached wraps a Provider: it refreshes on an interval and falls back to the
// last good list (in memory and on disk) when the source fails.
type Cached struct {
	inner   Provider
	refresh time.Duration
	file    string

	mu      sync.Mutex
	last    []model.Server
	fetched time.Time
	lastErr error
}

// NewCached returns a caching wrapper. file may be "" to disable disk cache.
func NewCached(inner Provider, refresh time.Duration, file string) *Cached {
	c := &Cached{inner: inner, refresh: refresh, file: file}
	if file != "" {
		if b, err := os.ReadFile(file); err == nil {
			_ = json.Unmarshal(b, &c.last)
		}
	}
	return c
}

func (c *Cached) Name() string { return c.inner.Name() + " (cached)" }

// LastError reports the last refresh failure, if any, for the heartbeat.
func (c *Cached) LastError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastErr
}

func (c *Cached) List(ctx context.Context, region string) ([]model.Server, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.last) > 0 && time.Since(c.fetched) < c.refresh {
		return c.last, nil
	}
	servers, err := c.inner.List(ctx, region)
	if err != nil {
		c.lastErr = err
		if len(c.last) > 0 {
			return c.last, nil // serve stale
		}
		return nil, err
	}
	c.lastErr = nil
	c.last, c.fetched = servers, time.Now()
	if c.file != "" {
		if b, err := json.Marshal(servers); err == nil {
			_ = os.MkdirAll(filepath.Dir(c.file), 0o750)
			_ = os.WriteFile(c.file, b, 0o600)
		}
	}
	return servers, nil
}

// ---------------------------------------------------------------------- SQL

type sqlProvider struct {
	pool  *pgxpool.Pool
	query string
}

func newSQL(dsn, password, query string) (Provider, error) {
	if dsn == "" {
		return nil, errors.New("inventory.sql.dsn is empty")
	}
	if password != "" && !strings.Contains(dsn, "password=") {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		dsn += sep + "password=" + password
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("inventory sql: %w", err)
	}
	cfg.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return nil, err
	}
	return &sqlProvider{pool: pool, query: query}, nil
}

func (s *sqlProvider) Name() string { return "sql" }

// List runs the configured query. The query must return columns in this order:
// id, hostname, bmc_ip, region, vendor (vendor may be NULL). Region filtering
// is done here so any inventory query works unchanged.
func (s *sqlProvider) List(ctx context.Context, region string) ([]model.Server, error) {
	rows, err := s.pool.Query(ctx, s.query)
	if err != nil {
		return nil, fmt.Errorf("inventory sql: %w", err)
	}
	defer rows.Close()
	var out []model.Server
	for rows.Next() {
		var sv model.Server
		var vendor *string
		if err := rows.Scan(&sv.ID, &sv.Hostname, &sv.BMCAddr, &sv.Region, &vendor); err != nil {
			return nil, fmt.Errorf("inventory sql scan: %w", err)
		}
		if vendor != nil {
			sv.Vendor = *vendor
		}
		if region == "" || sv.Region == region {
			out = append(out, sv)
		}
	}
	return out, rows.Err()
}

// --------------------------------------------------------------------- REST

type restProvider struct {
	url, path, token string
	client           *http.Client
}

func newREST(url, path, token string) Provider {
	return &restProvider{url: url, path: path, token: token, client: &http.Client{Timeout: 30 * time.Second}}
}

func (r *restProvider) Name() string { return "rest" }

func (r *restProvider) List(ctx context.Context, region string) ([]model.Server, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("inventory rest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("inventory rest: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("inventory rest: decode: %w", err)
	}
	// Walk the dotted json_path ("data.servers") down to the array.
	node := raw
	if r.path != "" {
		for _, key := range strings.Split(r.path, ".") {
			m, ok := node.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("inventory rest: json_path %q not found", r.path)
			}
			node = m[key]
		}
	}
	arr, err := json.Marshal(node)
	if err != nil {
		return nil, err
	}
	var all []model.Server
	if err := json.Unmarshal(arr, &all); err != nil {
		return nil, fmt.Errorf("inventory rest: items are not servers: %w", err)
	}
	return filterRegion(all, region), nil
}

// ---------------------------------------------------------------------- CSV

type csvProvider struct{ path string }

func (c *csvProvider) Name() string { return "csv" }

// List reads a CSV with a header line: id,hostname,bmc_ip,region[,vendor].
func (c *csvProvider) List(_ context.Context, region string) ([]model.Server, error) {
	f, err := os.Open(c.path)
	if err != nil {
		return nil, fmt.Errorf("inventory csv: %w", err)
	}
	defer f.Close()
	rd := csv.NewReader(f)
	rd.TrimLeadingSpace = true
	header, err := rd.Read()
	if err != nil {
		return nil, fmt.Errorf("inventory csv: header: %w", err)
	}
	idx := map[string]int{}
	for i, h := range header {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	for _, need := range []string{"id", "hostname", "bmc_ip", "region"} {
		if _, ok := idx[need]; !ok {
			return nil, fmt.Errorf("inventory csv: missing column %q", need)
		}
	}
	var all []model.Server
	for {
		rec, err := rd.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("inventory csv: %w", err)
		}
		get := func(k string) string {
			if i, ok := idx[k]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		all = append(all, model.Server{
			ID: get("id"), Hostname: get("hostname"), BMCAddr: get("bmc_ip"),
			Region: get("region"), Vendor: get("vendor"),
		})
	}
	return filterRegion(all, region), nil
}

func filterRegion(all []model.Server, region string) []model.Server {
	if region == "" {
		return all
	}
	out := all[:0:0]
	for _, s := range all {
		if s.Region == region {
			out = append(out, s)
		}
	}
	return out
}
