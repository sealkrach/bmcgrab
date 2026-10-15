// Package redfish is a small, dependency-free Redfish client plus a vendor
// adapter layer that normalizes OEM differences into model.Sample values.
//
// A raw JSON client (rather than a typed SDK) is used on purpose: the OEM
// extensions that carry CPU/RAM usage are not part of the DMTF schemas, and
// adapters need to reach into arbitrary JSON without fighting a type system.
package redfish

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ErrUnauthorized is returned on HTTP 401 so the collector can invalidate the
// cached credential and retry once with a fresh one.
var ErrUnauthorized = errors.New("redfish: unauthorized")

// ErrNotFound is returned on HTTP 404; adapters use it to mark "unsupported".
var ErrNotFound = errors.New("redfish: not found")

// ClientOptions configure the shared HTTP transport.
type ClientOptions struct {
	CAFile             string
	InsecureSkipVerify bool
	Timeout            time.Duration
	MaxConnsPerHost    int
}

// Client is safe for concurrent use; one per collector process.
type Client struct {
	http *http.Client
}

// NewClient builds the transport once. Credentials are passed per call.
func NewClient(o ClientOptions) (*Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: o.InsecureSkipVerify} //nolint:gosec // lab flag only
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("redfish: read ca: %w", err)
		}
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("redfish: ca file holds no certificate")
		}
		tlsCfg.RootCAs = pool
	}
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.MaxConnsPerHost <= 0 {
		o.MaxConnsPerHost = 4
	}
	tr := &http.Transport{
		TLSClientConfig:     tlsCfg,
		MaxIdleConns:        1024,
		MaxConnsPerHost:     o.MaxConnsPerHost,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &Client{http: &http.Client{Transport: tr, Timeout: o.Timeout}}, nil
}

// Target is one BMC endpoint with its credential.
type Target struct {
	BaseURL  string // https://10.0.0.1
	Username string
	Password string
}

// Get fetches a Redfish path and decodes the JSON object.
func (c *Client) Get(ctx context.Context, t Target, path string) (map[string]any, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(t.Username, t.Password)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("OData-Version", "4.0")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("redfish GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, ErrUnauthorized
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	case resp.StatusCode >= 300:
		return nil, fmt.Errorf("redfish GET %s: HTTP %d", path, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("redfish GET %s: decode: %w", path, err)
	}
	return out, nil
}

// ----------------------------------------------------------- JSON helpers

// Str walks a dotted path ("Oem.Dell.Foo") and returns the string value.
func Str(m map[string]any, path string) string {
	v := walk(m, path)
	s, _ := v.(string)
	return s
}

// Num walks a dotted path and returns a float64, ok=false if absent/not numeric.
func Num(m map[string]any, path string) (float64, bool) {
	switch v := walk(m, path).(type) {
	case float64:
		return v, true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	case int:
		return float64(v), true
	}
	return 0, false
}

// Arr walks a dotted path and returns an array of objects.
func Arr(m map[string]any, path string) []map[string]any {
	raw, _ := walk(m, path).([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, it := range raw {
		if o, ok := it.(map[string]any); ok {
			out = append(out, o)
		}
	}
	return out
}

// Obj walks a dotted path and returns an object.
func Obj(m map[string]any, path string) map[string]any {
	o, _ := walk(m, path).(map[string]any)
	return o
}

func walk(m map[string]any, path string) any {
	if path == "" {
		return m
	}
	var cur any = m
	for _, k := range strings.Split(path, ".") {
		o, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = o[k]
	}
	return cur
}

// ODataID returns the @odata.id of an object, or "".
func ODataID(m map[string]any) string { s, _ := m["@odata.id"].(string); return s }

// MembersOf returns the @odata.id of each Members[] entry of a collection.
func MembersOf(m map[string]any) []string {
	var out []string
	for _, mm := range Arr(m, "Members") {
		if id := ODataID(mm); id != "" {
			out = append(out, id)
		}
	}
	return out
}

// Enabled reports whether a Redfish Status says the resource is usable.
func Enabled(m map[string]any) bool {
	st := Str(m, "Status.State")
	return st == "" || st == "Enabled"
}
