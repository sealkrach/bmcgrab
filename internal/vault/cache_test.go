package vault

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeVault is an in-memory CCP: one password per account, rotatable, with a
// call counter and an optional failure switch.
type fakeVault struct {
	mu    sync.Mutex
	pass  map[Ref]string
	calls atomic.Int64
	fail  atomic.Bool
	delay time.Duration
}

func newFake(accts map[Ref]string) *fakeVault { return &fakeVault{pass: accts} }

func (f *fakeVault) Name() string { return "fake" }
func (f *fakeVault) Fetch(_ context.Context, r Ref) (Credential, error) {
	f.calls.Add(1)
	time.Sleep(f.delay)
	if f.fail.Load() {
		return Credential{}, errors.New("vault down")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.pass[r]
	if !ok {
		return Credential{}, errors.New("unknown account")
	}
	return Credential{Username: "root", Password: p}, nil
}
func (f *fakeVault) rotate(r Ref, p string) { f.mu.Lock(); f.pass[r] = p; f.mu.Unlock() }

type clock struct{ t atomic.Int64 }

func (c *clock) now() time.Time          { return time.Unix(0, c.t.Load()) }
func (c *clock) advance(d time.Duration) { c.t.Add(int64(d)) }

var (
	shared = Ref{Safe: "S", Object: "shared"}
	a1     = Ref{Safe: "S", Object: "a1"}
	a2     = Ref{Safe: "S", Object: "a2"}
)

func newTestCache(f Fetcher, mode Mode) (*Cache, *clock) {
	clk := &clock{}
	clk.t.Store(time.Now().UnixNano())
	return NewCache(f, CacheConfig{
		Mode: mode, Default: shared, TTL: time.Hour, StaleMax: 2 * time.Hour,
		Jitter: 0.0001, MinRefetch: time.Minute, FailBackoff: 10 * time.Second, Now: clk.now,
	}), clk
}

func TestResolveModes(t *testing.T) {
	f := newFake(nil)
	cases := []struct {
		mode    Mode
		in      string
		want    Ref
		wantErr bool
	}{
		{ModeShared, "", shared, false},
		{ModeShared, "S/a1", shared, false}, // ignored
		{ModeAuto, "", shared, false},
		{ModeAuto, "S/a1", a1, false},
		{ModeAuto, "a1", a1, false}, // Safe from default
		{ModePerAsset, "", Ref{}, true},
		{ModePerAsset, "S/a1", a1, false},
		{ModeAuto, "/x", Ref{}, true},
	}
	for _, tc := range cases {
		c, _ := newTestCache(f, tc.mode)
		got, err := c.Resolve(tc.in)
		if (err != nil) != tc.wantErr || (!tc.wantErr && got != tc.want) {
			t.Errorf("%s %q: got %v err=%v", tc.mode, tc.in, got, err)
		}
	}
}

func TestSingleFlightSharedAccount(t *testing.T) {
	f := newFake(map[Ref]string{shared: "pw"})
	f.delay = 50 * time.Millisecond
	c, _ := newTestCache(f, ModeShared)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if cr, err := c.Get(context.Background(), Ref{}); err != nil || cr.Password != "pw" {
				t.Errorf("get: %v %q", err, cr.Password)
			}
		}()
	}
	wg.Wait()
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("200 concurrent gets made %d vault calls, want 1", n)
	}
}

func TestPerAssetAccountsAreIndependent(t *testing.T) {
	f := newFake(map[Ref]string{a1: "p1", a2: "p2"})
	c, _ := newTestCache(f, ModePerAsset)
	c1, _ := c.Get(context.Background(), a1)
	c2, _ := c.Get(context.Background(), a2)
	if c1.Password != "p1" || c2.Password != "p2" || c1.Version == c2.Version {
		t.Fatalf("bad credentials: %+v %+v", c1, c2)
	}
}

func TestTTLExpiryRefetches(t *testing.T) {
	f := newFake(map[Ref]string{a1: "p1"})
	c, clk := newTestCache(f, ModeAuto)
	_, _ = c.Get(context.Background(), a1)
	_, _ = c.Get(context.Background(), a1)
	if f.calls.Load() != 1 {
		t.Fatal("second get should hit the cache")
	}
	clk.advance(61 * time.Minute)
	_, _ = c.Get(context.Background(), a1)
	if f.calls.Load() != 2 {
		t.Fatal("expired entry should refetch")
	}
}

func TestStaleServedWhileVaultDownThenBounded(t *testing.T) {
	f := newFake(map[Ref]string{a1: "p1"})
	stale := 0
	c, clk := newTestCache(f, ModeAuto)
	c.cfg.Hooks.OnStale = func() { stale++ }
	_, _ = c.Get(context.Background(), a1)
	f.fail.Store(true)
	clk.advance(90 * time.Minute) // expired, within StaleMax
	cr, err := c.Get(context.Background(), a1)
	if err != nil || cr.Password != "p1" || stale == 0 {
		t.Fatalf("expected stale p1, got %q err=%v stale=%d", cr.Password, err, stale)
	}
	clk.advance(3 * time.Hour) // beyond StaleMax
	if _, err := c.Get(context.Background(), a1); err == nil {
		t.Fatal("secret past StaleMax must not be served")
	}
}

func TestFailBackoffAvoidsHammering(t *testing.T) {
	f := newFake(map[Ref]string{a1: "p1"})
	f.fail.Store(true)
	c, clk := newTestCache(f, ModeAuto)
	for i := 0; i < 20; i++ {
		_, _ = c.Get(context.Background(), a1)
	}
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("got %d vault calls during backoff, want 1", n)
	}
	clk.advance(11 * time.Second)
	_, _ = c.Get(context.Background(), a1)
	if f.calls.Load() != 2 {
		t.Fatal("backoff should expire")
	}
}

func TestRotationInvalidateAndVersion(t *testing.T) {
	f := newFake(map[Ref]string{a1: "old"})
	c, clk := newTestCache(f, ModeAuto)
	first, _ := c.Get(context.Background(), a1)

	f.rotate(a1, "new")
	// Too soon after fetch: Invalidate is ignored (BMC-side problem guard).
	c.Invalidate(a1, first.Version)
	if cr, _ := c.Get(context.Background(), a1); cr.Password != "old" {
		t.Fatal("invalidate right after fetch must be ignored")
	}

	clk.advance(2 * time.Minute)
	c.Invalidate(a1, first.Version)
	second, err := c.Get(context.Background(), a1)
	if err != nil || second.Password != "new" || second.Version == first.Version {
		t.Fatalf("rotation not picked up: %+v err=%v", second, err)
	}

	// A stale caller invalidating with the old version must not drop the new secret.
	calls := f.calls.Load()
	c.Invalidate(a1, first.Version)
	_, _ = c.Get(context.Background(), a1)
	if f.calls.Load() != calls {
		t.Fatal("invalidate with an outdated version must be a no-op")
	}
}

func TestInvalidateWithUnchangedPasswordKeepsVersion(t *testing.T) {
	f := newFake(map[Ref]string{a1: "same"})
	c, clk := newTestCache(f, ModeAuto)
	first, _ := c.Get(context.Background(), a1)
	clk.advance(2 * time.Minute)
	c.Invalidate(a1, first.Version)
	again, _ := c.Get(context.Background(), a1)
	if again.Version != first.Version {
		t.Fatal("same password must keep its version so callers do not retry pointlessly")
	}
	// A rejected secret is never served stale.
	c.Invalidate(a1, again.Version) // too soon (just refetched) → ignored
	clk.advance(2 * time.Minute)
	c.Invalidate(a1, again.Version)
	f.fail.Store(true)
	if _, err := c.Get(context.Background(), a1); err == nil {
		t.Fatal("rejected secret must not be served stale")
	}
}

func TestRefreshOnlyDueAndDetectsRotation(t *testing.T) {
	f := newFake(map[Ref]string{a1: "p1", a2: "p2"})
	c, clk := newTestCache(f, ModeAuto)
	rep := c.Refresh(context.Background(), []Ref{a1, a2, a1}, false)
	if rep.Requested != 2 || rep.Fetched != 2 || rep.Changed != 0 {
		t.Fatalf("initial refresh: %+v", rep)
	}
	rep = c.Refresh(context.Background(), []Ref{a1, a2}, false)
	if rep.Skipped != 2 || rep.Fetched != 0 {
		t.Fatalf("fresh entries must be skipped: %+v", rep)
	}
	f.rotate(a2, "p2b")
	rep = c.Refresh(context.Background(), []Ref{a1, a2}, true)
	if rep.Fetched != 2 || rep.Changed != 1 {
		t.Fatalf("forced refresh must detect the rotation of a2 only: %+v", rep)
	}
	clk.advance(50 * time.Minute) // past 80 % of the TTL
	rep = c.Refresh(context.Background(), []Ref{a1, a2}, false)
	if rep.Fetched != 2 {
		t.Fatalf("refresh-ahead should refetch: %+v", rep)
	}
}

func TestRefreshReportsFailuresWithoutSecrets(t *testing.T) {
	f := newFake(map[Ref]string{a1: "p1"})
	c, _ := newTestCache(f, ModeAuto)
	rep := c.Refresh(context.Background(), []Ref{a1, a2}, true)
	if rep.Failed != 1 || rep.Fetched != 1 || len(rep.Errors) != 1 || rep.Errors[0].Ref != "S/a2" {
		t.Fatalf("report: %+v", rep)
	}
}

func TestParseRef(t *testing.T) {
	if r, err := ParseRef(" S/o "); err != nil || r != (Ref{"S", "o"}) {
		t.Fatalf("%v %v", r, err)
	}
	if r, _ := ParseRef("o"); r != (Ref{Object: "o"}) {
		t.Fatalf("%v", r)
	}
	if _, err := ParseRef("S/"); err == nil {
		t.Fatal("want error")
	}
}

func TestProtectedStoreRoundTripAndCache(t *testing.T) {
	st, err := ProtectedStore()
	if err != nil {
		t.Skipf("protected memory not available here: %v", err)
	}
	f := newFake(map[Ref]string{a1: "s3cret-é"})
	clk := &clock{}
	clk.t.Store(time.Now().UnixNano())
	c := NewCache(f, CacheConfig{Mode: ModeAuto, Default: shared, Store: st, Now: clk.now})
	got, err := c.Get(context.Background(), a1)
	if err != nil || got.Password != "s3cret-é" {
		t.Fatalf("got %q err=%v", got.Password, err)
	}
	if !strings.Contains(c.Name(), "protected") {
		t.Fatalf("name %q", c.Name())
	}
}
