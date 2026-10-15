package collector

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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

// TestCycleWithoutDatabase runs a full cycle against five fake BMCs with no
// database: the cycle must land in the local buffer, with one server failed
// (bad credential) and one unsupported family (Supermicro CPU).
func TestCycleWithoutDatabase(t *testing.T) {
	dir := t.TempDir()
	bmcs := []*redfishmock.Server{
		redfishmock.New(redfishmock.ProfileDell, "svc", "pw"),
		redfishmock.New(redfishmock.ProfileHPE, "svc", "pw"),
		redfishmock.New(redfishmock.ProfileLenovo, "svc", "pw"),
		redfishmock.New(redfishmock.ProfileSupermicro, "svc", "pw"),
		redfishmock.New(redfishmock.ProfileGeneric, "svc", "other-password"), // auth will fail
	}
	for _, b := range bmcs {
		defer b.Close()
	}
	bmcs[0].BadTemp = true // one out-of-range reading → rejected sample, family stays collected

	inv := filepath.Join(dir, "inventory.csv")
	var sb strings.Builder
	sb.WriteString("id,hostname,bmc_ip,region,vendor\n")
	for i, b := range bmcs {
		sb.WriteString("srv-" + string(rune('a'+i)) + ",host-" + string(rune('a'+i)) + "," + b.URL + ",eu-west-1,\n")
	}
	sb.WriteString("srv-z,other-region," + bmcs[0].URL + ",us-east-1,\n") // filtered out
	if err := os.WriteFile(inv, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Inventory.Type = "csv"
	cfg.Inventory.CSV.Path = inv
	cfg.TLS.InsecureSkipVerify = true
	cfg.Collect.Retries = 0
	cfg.Collect.Timeout = 5 * time.Second
	cache := filepath.Join(dir, "config.json")
	if err := cfg.SaveCache(cache); err != nil {
		t.Fatal(err)
	}

	local := &config.Local{Region: "eu-west-1"}
	local.Local.ConfigCache = cache
	local.Local.BufferDir = filepath.Join(dir, "buffer")
	buf, _ := buffer.New(local.Local.BufferDir, 1<<30)

	t.Setenv("U", "svc")
	t.Setenv("P", "pw")
	c := New(Options{
		Local: local, Store: nil, Vault: vault.NewEnv("U", "P"), Registry: vendors.All(), Buffer: buf,
		Metrics: telemetry.NewMetrics("test"), Log: slog.New(slog.NewTextHandler(os.Stderr, nil)), Version: "test", Lab: true,
	})
	if err := c.RunOnce(context.Background()); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if buf.Segments() != 1 {
		t.Fatalf("buffer segments = %d, want 1", buf.Segments())
	}

	var got []*model.Result
	_, err := buf.Replay(context.Background(), func(_ context.Context, rs []*model.Result) error { got = rs; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("results = %d, want 5 (region filter)", len(got))
	}
	byHost := map[string]*model.Result{}
	for _, r := range got {
		byHost[r.Server.Hostname] = r
	}
	if s := byHost["host-e"].Status(); s != "failed" || !strings.Contains(byHost["host-e"].Err, "unauthorized") {
		t.Errorf("bad-credential server: status=%s err=%q", s, byHost["host-e"].Err)
	}
	if s := byHost["host-d"].Status(); s != "ok" {
		t.Errorf("supermicro status = %s, want ok (unsupported is not an error): %+v", s, byHost["host-d"].Families)
	}
	for _, f := range byHost["host-d"].Families {
		if f.Family == model.FamilyCPU && f.State != model.StateUnsupported {
			t.Errorf("supermicro cpu state = %s", f.State)
		}
	}
	dell := byHost["host-a"]
	if dell.Vendor != "dell" || dell.Status() != "ok" {
		t.Errorf("dell: vendor=%s status=%s", dell.Vendor, dell.Status())
	}
	for _, f := range dell.Families {
		if f.Family == model.FamilyThermal && !strings.Contains(f.Reason, "1 of 2 readings rejected") {
			t.Errorf("dell thermal reason = %q", f.Reason)
		}
	}
}
