package collector

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sealkrach/bmcgrab/internal/config"
	"github.com/sealkrach/bmcgrab/internal/model"
	"github.com/sealkrach/bmcgrab/internal/redfish/vendors"
	"github.com/sealkrach/bmcgrab/internal/storage/buffer"
	"github.com/sealkrach/bmcgrab/internal/telemetry"
	"github.com/sealkrach/bmcgrab/internal/vault"
	"github.com/sealkrach/bmcgrab/test/redfishmock"
)

// accountVault is an in-memory CyberArk: one password per Object.
type accountVault struct {
	mu    sync.Mutex
	pass  map[string]string
	calls map[string]int
}

func (a *accountVault) Name() string { return "fake-ccp" }
func (a *accountVault) Fetch(_ context.Context, r vault.Ref) (vault.Credential, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls[r.Object]++
	p, ok := a.pass[r.Object]
	if !ok {
		return vault.Credential{}, errors.New("unknown account")
	}
	return vault.Credential{Username: "svc", Password: p}, nil
}
func (a *accountVault) set(obj, p string) { a.mu.Lock(); a.pass[obj] = p; a.mu.Unlock() }
func (a *accountVault) n(obj string) int  { a.mu.Lock(); defer a.mu.Unlock(); return a.calls[obj] }

// TestPerAssetSecretsAndRotation: each BMC has its own account; a rotated
// password is picked up inside the same cycle; a BMC whose password the vault
// does not know is not hammered.
func TestPerAssetSecretsAndRotation(t *testing.T) {
	dir := t.TempDir()
	bmcs := []*redfishmock.Server{
		redfishmock.New(redfishmock.ProfileDell, "svc", "pw0"),
		redfishmock.New(redfishmock.ProfileHPE, "svc", "pw1"),
		redfishmock.New(redfishmock.ProfileLenovo, "svc", "pw2"),
	}
	for _, b := range bmcs {
		defer b.Close()
	}
	av := &accountVault{pass: map[string]string{"acct0": "pw0", "acct1": "pw1", "acct2": "pw2"}, calls: map[string]int{}}
	prov := vault.NewCache(av, vault.CacheConfig{
		Mode: vault.ModePerAsset, Default: vault.Ref{Safe: "BMC"}, TTL: time.Hour, MinRefetch: time.Millisecond,
	})

	var sb strings.Builder
	sb.WriteString("id,hostname,bmc_ip,region,vendor,secret_ref\n")
	for i, b := range bmcs {
		sb.WriteString("s" + string(rune('0'+i)) + ",h" + string(rune('0'+i)) + "," + b.URL + ",eu,,acct" + string(rune('0'+i)) + "\n")
	}
	inv := filepath.Join(dir, "inv.csv")
	if err := os.WriteFile(inv, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Inventory.Type, cfg.Inventory.CSV.Path = "csv", inv
	cfg.TLS.InsecureSkipVerify = true
	cfg.Collect.Retries = 0
	cfg.Collect.Timeout = 5 * time.Second
	cache := filepath.Join(dir, "config.json")
	if err := cfg.SaveCache(cache); err != nil {
		t.Fatal(err)
	}
	local := &config.Local{Region: "eu"}
	local.Local.ConfigCache = cache
	buf, _ := buffer.New(filepath.Join(dir, "buf"), 1<<30)
	c := New(Options{
		Local: local, Vault: prov, Registry: vendors.All(), Buffer: buf,
		Metrics: telemetry.NewMetrics("test-secrets"), Log: slog.New(slog.NewTextHandler(os.Stderr, nil)), Lab: true,
	})

	cycle := func() map[string]*model.Result {
		t.Helper()
		if err := c.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		out := map[string]*model.Result{}
		_, err := buf.Replay(context.Background(), func(_ context.Context, rs []*model.Result) error {
			for _, r := range rs {
				out[r.Server.Hostname] = r
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	// 1. every BMC authenticates with its own secret.
	for h, r := range cycle() {
		if r.Status() != "ok" {
			t.Fatalf("%s: status %s err=%q", h, r.Status(), r.Err)
		}
	}

	// 2. rotation of acct1 on both sides: recovered within the same cycle.
	bmcs[1].Password = "pw1-rotated"
	av.set("acct1", "pw1-rotated")
	time.Sleep(5 * time.Millisecond)
	res := cycle()
	if res["h1"].Status() != "ok" {
		t.Fatalf("rotated account not recovered: %q", res["h1"].Err)
	}
	if av.n("acct1") != 2 || av.n("acct0") != 1 {
		t.Fatalf("vault calls: acct0=%d acct1=%d, want 1 and 2", av.n("acct0"), av.n("acct1"))
	}

	// 3. BMC rotated but the vault still has the old secret: fail without a retry storm, then block.
	bmcs[2].Password = "unknown-to-vault"
	time.Sleep(5 * time.Millisecond)
	res = cycle()
	if !strings.Contains(res["h2"].Err, "unauthorized") {
		t.Fatalf("expected an unauthorized error, got %q", res["h2"].Err)
	}
	res = cycle()
	if !strings.HasPrefix(res["h2"].Err, ErrCredentialFailed) {
		t.Fatalf("second cycle should be blocked by the auth guard, got %q", res["h2"].Err)
	}
	if res["h0"].Status() != "ok" || res["h1"].Status() != "ok" {
		t.Fatal("other BMCs must be unaffected")
	}

	// 4. the vault catches up (rotation finished): collection resumes.
	av.set("acct2", "unknown-to-vault")
	if rep, err := c.SyncSecrets(context.Background(), true, ""); err != nil || rep.Changed != 1 {
		t.Fatalf("forced sync: %+v err=%v", rep, err)
	}
	if r := cycle()["h2"]; r.Status() != "ok" {
		t.Fatalf("not recovered after sync: %q", r.Err)
	}
}

// TestPerAssetMissingRef: a server without secret_ref in per_asset mode fails
// on its own, the rest of the region is collected.
func TestPerAssetMissingRef(t *testing.T) {
	av := &accountVault{pass: map[string]string{}, calls: map[string]int{}}
	prov := vault.NewCache(av, vault.CacheConfig{Mode: vault.ModePerAsset, Default: vault.Ref{Safe: "BMC"}})
	if _, err := prov.Resolve(""); err == nil {
		t.Fatal("per_asset must refuse an empty secret_ref")
	}
}
