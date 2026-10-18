package vault_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/sealkrach/bmcgrab/internal/vault"
	"github.com/sealkrach/bmcgrab/test/fakeccp"
)

func newCCP(t *testing.T) *fakeccp.Server {
	t.Helper()
	s, err := fakeccp.New(t.TempDir(), "BMCGrab")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func provider(t *testing.T, s *fakeccp.Server, mod func(*vault.CyberArkConfig)) vault.Provider {
	t.Helper()
	cfg := vault.CyberArkConfig{
		URL: s.URL, AppID: "BMCGrab", Safe: "BMC", Object: "shared",
		ClientCert: s.ClientCertFile, ClientKey: s.ClientKeyFile, CAFile: s.CAFile, Mode: vault.ModeAuto,
	}
	if mod != nil {
		mod(&cfg)
	}
	p, err := vault.NewCyberArk(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCCPSharedAndPerAssetOverMTLS(t *testing.T) {
	s := newCCP(t)
	s.Set("BMC", "shared", "svc-shared", "pw-shared")
	s.Set("BMC-Dell", "idrac-07", "root", "pw-07")
	p := provider(t, s, nil)

	def, err := p.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	c1, err := p.Get(context.Background(), def)
	if err != nil || c1.Username != "svc-shared" || c1.Password != "pw-shared" {
		t.Fatalf("shared: %+v err=%v", c1, err)
	}
	ref, _ := p.Resolve("BMC-Dell/idrac-07")
	c2, err := p.Get(context.Background(), ref)
	if err != nil || c2.Username != "root" || c2.Password != "pw-07" {
		t.Fatalf("per asset: %+v err=%v", c2, err)
	}
}

func TestCCPSingleFlightAndCacheOverHTTP(t *testing.T) {
	s := newCCP(t)
	s.Set("BMC", "shared", "svc", "pw")
	s.SetDelay(50 * 1000 * 1000) // 50 ms
	p := provider(t, s, nil)
	var wg sync.WaitGroup
	for i := 0; i < 300; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.Get(context.Background(), vault.Ref{}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := s.Calls("BMC", "shared"); n != 1 {
		t.Fatalf("300 concurrent gets reached the CCP %d times, want 1", n)
	}
}

func TestCCPRotationPickedUpByForcedRefresh(t *testing.T) {
	s := newCCP(t)
	s.Set("BMC", "a", "root", "old")
	p := provider(t, s, nil)
	ref, _ := p.Resolve("BMC/a")
	first, _ := p.Get(context.Background(), ref)
	s.Set("BMC", "a", "root", "new")
	rep := p.Refresh(context.Background(), []vault.Ref{ref}, true)
	if rep.Changed != 1 || rep.Failed != 0 {
		t.Fatalf("report %+v", rep)
	}
	got, _ := p.Get(context.Background(), ref)
	if got.Password != "new" || got.Version == first.Version {
		t.Fatalf("rotation not visible: %+v", got)
	}
}

func TestCCPErrorsNeverLeakTheBody(t *testing.T) {
	s := newCCP(t)
	s.Set("BMC", "shared", "svc", "pw")

	// 404: unknown account. The CCP body names the query; the error must not.
	p := provider(t, s, nil)
	_, err := p.Get(context.Background(), vault.Ref{Safe: "BMC", Object: "ghost"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") || strings.Contains(err.Error(), "ghost") || strings.Contains(err.Error(), "APPAP") {
		t.Fatalf("404 error = %v", err)
	}

	// 403: wrong AppID.
	bad := provider(t, s, func(c *vault.CyberArkConfig) { c.AppID = "Other" })
	_, err = bad.Get(context.Background(), vault.Ref{})
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") || strings.Contains(err.Error(), "secret-looking") {
		t.Fatalf("403 error = %v", err)
	}

	// 500 with a cold cache: error. With a warm cache and a fresh TTL: still served.
	s.ForceStatus(500)
	if _, err := provider(t, s, nil).Get(context.Background(), vault.Ref{}); err == nil {
		t.Fatal("500 on a cold cache must fail")
	}
}

func TestCCPStaleServedWhenDown(t *testing.T) {
	s := newCCP(t)
	s.Set("BMC", "shared", "svc", "pw")
	// A 1 ns TTL expires immediately; StaleMax keeps the secret usable.
	p := provider(t, s, func(c *vault.CyberArkConfig) { c.CacheTTL = 1; c.StaleMax = 1 << 62 })
	if _, err := p.Get(context.Background(), vault.Ref{}); err != nil {
		t.Fatal(err)
	}
	s.ForceStatus(503)
	got, err := p.Get(context.Background(), vault.Ref{})
	if err != nil || got.Password != "pw" {
		t.Fatalf("stale not served: %+v err=%v", got, err)
	}
}

func TestCCPRequiresClientCertificate(t *testing.T) {
	s := newCCP(t)
	s.Set("BMC", "shared", "svc", "pw")
	p := provider(t, s, func(c *vault.CyberArkConfig) { c.ClientCert, c.ClientKey = "", "" })
	if _, err := p.Get(context.Background(), vault.Ref{}); err == nil {
		t.Fatal("the fake CCP must refuse a client without certificate")
	}
}

func TestCCPUntrustedServerRejected(t *testing.T) {
	s := newCCP(t)
	s.Set("BMC", "shared", "svc", "pw")
	p := provider(t, s, func(c *vault.CyberArkConfig) { c.CAFile = "" }) // system roots only
	if _, err := p.Get(context.Background(), vault.Ref{}); err == nil {
		t.Fatal("a server certificate from an unknown CA must be rejected")
	}
}
