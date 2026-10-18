// Package collector runs the collection cycle: load config, load inventory,
// fan servers out to a worker pool, validate, write (or buffer), heartbeat.
package collector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sony/gobreaker/v2"

	"github.com/sealkrach/bmcgrab/internal/config"
	"github.com/sealkrach/bmcgrab/internal/inventory"
	"github.com/sealkrach/bmcgrab/internal/model"
	"github.com/sealkrach/bmcgrab/internal/quality"
	"github.com/sealkrach/bmcgrab/internal/redfish"
	"github.com/sealkrach/bmcgrab/internal/storage/buffer"
	"github.com/sealkrach/bmcgrab/internal/storage/timescale"
	"github.com/sealkrach/bmcgrab/internal/telemetry"
	"github.com/sealkrach/bmcgrab/internal/vault"
)

// Options wire the collector's dependencies.
type Options struct {
	Local    *config.Local
	Store    *timescale.Store // may be nil-safe: writes fall back to the buffer
	Vault    vault.Provider
	Registry *redfish.Registry
	Buffer   *buffer.Buffer
	Metrics  *telemetry.Metrics
	Log      *slog.Logger
	Version  string
	Lab      bool

	// AuthRetry: a BMC that rejected a password is not contacted again with the
	// same password for this long (protects against BMC account lockout).
	AuthRetry time.Duration
	// SyncInterval: period of the background secret synchronisation; 0 disables.
	SyncInterval time.Duration
}

// Collector is one regional instance.
type Collector struct {
	o        Options
	instance string

	mu       sync.Mutex
	central  *config.Central
	inv      *inventory.Cached
	invType  string
	client   *redfish.Client
	clientTS bool     // insecure flag the client was built with
	breakers sync.Map // bmc addr → *gobreaker.CircuitBreaker[struct{}]
	authFail sync.Map // server id → authFailure
	lastErr  error

	lastPollErr string // only touched by syncLoop
}

// authFailure remembers which secret version a BMC rejected, and when.
type authFailure struct {
	version uint64
	at      time.Time
}

// Error prefixes on Result.Err for credential problems; the UI and queries can
// tell them apart from BMC transport failures.
const (
	ErrCredentialPending = "credential_pending" // the vault could not provide a secret yet
	ErrCredentialFailed  = "credential_failed"  // the BMC rejected the secret; waiting for rotation
)

// New returns a collector ready to Run.
func New(o Options) *Collector {
	host, _ := os.Hostname()
	return &Collector{o: o, instance: host}
}

// Healthy is used by /healthz: unhealthy if the last cycle failed outright.
func (c *Collector) Healthy() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastErr
}

// Run loops until ctx is cancelled.
func (c *Collector) Run(ctx context.Context) error {
	go c.syncLoop(ctx)
	for {
		start := time.Now()
		cfg := c.loadConfig(ctx)
		c.mu.Lock()
		c.central = cfg
		c.mu.Unlock()
		err := c.cycle(ctx, cfg)
		c.mu.Lock()
		c.lastErr = err
		c.mu.Unlock()
		if err != nil {
			c.o.Log.Error("cycle failed", "err", err)
		}
		wait := cfg.Collect.Interval - time.Since(start)
		if wait < 10*time.Second {
			wait = 10 * time.Second
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// RunOnce executes a single cycle (used by `check` and tests).
func (c *Collector) RunOnce(ctx context.Context) error {
	return c.cycle(ctx, c.loadConfig(ctx))
}

// loadConfig: DB → local cache → defaults, in that order.
func (c *Collector) loadConfig(ctx context.Context) *config.Central {
	if c.o.Store != nil {
		if cfg, err := c.o.Store.LoadConfig(ctx); err == nil {
			_ = cfg.SaveCache(c.o.Local.Local.ConfigCache)
			c.o.Metrics.ConfigVersion.Set(float64(cfg.Version))
			return cfg
		} else {
			c.o.Log.Warn("central config unreachable, using cache", "err", err)
		}
	}
	if cfg, err := config.LoadCache(c.o.Local.Local.ConfigCache); err == nil {
		return cfg
	}
	c.o.Log.Warn("no config cache, using defaults")
	return config.Default()
}

func (c *Collector) ensureDeps(cfg *config.Central) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inv == nil || c.invType != cfg.Inventory.Type {
		p, err := inventory.New(cfg)
		if err != nil {
			return err
		}
		cacheFile := strings.TrimSuffix(c.o.Local.Local.ConfigCache, ".json") + "-inventory.json"
		c.inv = inventory.NewCached(p, cfg.Inventory.Refresh, cacheFile)
		c.invType = cfg.Inventory.Type
	}
	insecure := cfg.TLS.InsecureSkipVerify && c.o.Lab
	if c.client == nil || c.clientTS != insecure {
		cl, err := redfish.NewClient(redfish.ClientOptions{
			CAFile: c.o.Local.TLS.CAFile, InsecureSkipVerify: insecure,
			Timeout: cfg.Collect.Timeout, MaxConnsPerHost: 4,
		})
		if err != nil {
			return err
		}
		c.client, c.clientTS = cl, insecure
	}
	return nil
}

func (c *Collector) breaker(addr string, cfg *config.Central) *gobreaker.CircuitBreaker[struct{}] {
	if b, ok := c.breakers.Load(addr); ok {
		return b.(*gobreaker.CircuitBreaker[struct{}])
	}
	b := gobreaker.NewCircuitBreaker[struct{}](gobreaker.Settings{
		Name:        addr,
		MaxRequests: 1,
		Timeout:     cfg.Breaker.Cooldown,
		ReadyToTrip: func(counts gobreaker.Counts) bool { return counts.ConsecutiveFailures >= cfg.Breaker.Failures },
	})
	actual, _ := c.breakers.LoadOrStore(addr, b)
	return actual.(*gobreaker.CircuitBreaker[struct{}])
}

func newCycleID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return time.Now().UTC().Format("20060102T1504") + "-" + hex.EncodeToString(b)
}

// cycle is one pass over the region.
func (c *Collector) cycle(ctx context.Context, cfg *config.Central) error {
	start := time.Now()
	cycleID := newCycleID()
	log := c.o.Log.With("cycle", cycleID, "region", c.o.Local.Region)

	if err := c.ensureDeps(cfg); err != nil {
		return fmt.Errorf("dependencies: %w", err)
	}

	servers, err := c.inv.List(ctx, c.o.Local.Region)
	if err != nil {
		c.o.Metrics.InventoryErrors.Inc()
		return fmt.Errorf("inventory: %w", err)
	}
	c.o.Metrics.InventorySize.Set(float64(len(servers)))

	families := enabledFamilies(cfg)
	validator := quality.FromConfig(cfg)

	// Fan out.
	jobs := make(chan model.Server)
	results := make([]*model.Result, 0, len(servers))
	var rmu sync.Mutex
	var wg sync.WaitGroup
	workers := cfg.Collect.Workers
	if workers > len(servers) && len(servers) > 0 {
		workers = len(servers)
	}
	var breakerOpen, rejectedTotal int64
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sv := range jobs {
				r := c.collectOne(ctx, cfg, sv, families, cycleID)
				rej := validator.Apply(r, r.Collected)
				for _, x := range rej {
					c.o.Metrics.Rejected.WithLabelValues(x.Sample.Name).Inc()
					log.Debug("sample rejected", "server", sv.Hostname, "metric", x.Sample.Name, "sensor", x.Sample.Sensor, "reason", x.Reason)
				}
				rmu.Lock()
				results = append(results, r)
				rejectedTotal += int64(len(rej))
				if strings.Contains(r.Err, "circuit breaker is open") {
					breakerOpen++
				}
				rmu.Unlock()
			}
		}()
	}
	for _, sv := range servers {
		select {
		case jobs <- sv:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()

	// Tally.
	var ok, partial, failed int
	unsupported := map[[2]string]int{}
	for _, r := range results {
		switch r.Status() {
		case "ok":
			ok++
		case "partial":
			partial++
		default:
			failed++
		}
		for _, f := range r.Families {
			if f.State == model.StateUnsupported {
				unsupported[[2]string{r.Vendor, string(f.Family)}]++
			}
		}
	}
	c.o.Metrics.CycleServers.WithLabelValues("ok").Set(float64(ok))
	c.o.Metrics.CycleServers.WithLabelValues("partial").Set(float64(partial))
	c.o.Metrics.CycleServers.WithLabelValues("failed").Set(float64(failed))
	c.o.Metrics.BreakerOpen.Set(float64(breakerOpen))
	c.o.Metrics.Unsupported.Reset()
	for k, n := range unsupported {
		c.o.Metrics.Unsupported.WithLabelValues(k[0], k[1]).Set(float64(n))
	}

	// Write: replay buffer first (keeps order), then this cycle; on failure buffer it.
	var invErr string
	if e := c.inv.LastError(); e != nil {
		invErr = e.Error()
	}
	writeErr := c.write(ctx, cycleID, results)
	c.o.Metrics.BufferBytes.Set(float64(c.o.Buffer.Size()))
	c.o.Metrics.BufferSegments.Set(float64(c.o.Buffer.Segments()))

	dur := time.Since(start)
	c.o.Metrics.CycleDuration.Observe(dur.Seconds())
	c.o.Metrics.LastCycle.Set(float64(time.Now().Unix()))

	if c.o.Store != nil {
		hb := timescale.Heartbeat{
			Region: c.o.Local.Region, Instance: c.instance, CycleID: cycleID, Version: c.o.Version, Time: time.Now().UTC(),
			ConfigVersion: cfg.Version, Servers: len(servers), OK: ok, Partial: partial, Failed: failed,
			BreakerOpen: int(breakerOpen), Rejected: int(rejectedTotal), Buffered: c.o.Buffer.Size(), Duration: dur, InventoryError: invErr,
		}
		if err := c.o.Store.WriteHeartbeat(ctx, hb); err != nil {
			log.Warn("heartbeat not written", "err", err)
		}
	}
	log.Info("cycle done", "servers", len(servers), "ok", ok, "partial", partial, "failed", failed,
		"breaker_open", breakerOpen, "rejected", rejectedTotal, "buffered_bytes", c.o.Buffer.Size(), "duration", dur.Round(time.Millisecond))
	return writeErr
}

func (c *Collector) write(ctx context.Context, cycleID string, results []*model.Result) error {
	if c.o.Store == nil {
		return c.o.Buffer.Write(cycleID, results)
	}
	// Replay older segments first so the database keeps chronological order.
	if n, err := c.o.Buffer.Replay(ctx, c.o.Store.WriteResults); err != nil {
		c.o.Metrics.DBWriteErrors.Inc()
		c.o.Log.Warn("database unreachable, buffering cycle", "replayed", n, "err", err)
		if berr := c.o.Buffer.Write(cycleID, results); berr != nil {
			return fmt.Errorf("db down and buffer failed: %w (db: %v)", berr, err)
		}
		return nil
	} else if n > 0 {
		c.o.Log.Info("buffer replayed", "segments", n)
	}
	if err := c.o.Store.WriteResults(ctx, results); err != nil {
		c.o.Metrics.DBWriteErrors.Inc()
		c.o.Log.Warn("write failed, buffering cycle", "err", err)
		if berr := c.o.Buffer.Write(cycleID, results); berr != nil {
			return fmt.Errorf("db write and buffer failed: %w (db: %v)", berr, err)
		}
	}
	return nil
}

// collectOne handles one server: credential → breaker → open session → adapter → retries.
func (c *Collector) collectOne(ctx context.Context, cfg *config.Central, sv model.Server, families []model.Family, cycleID string) *model.Result {
	start := time.Now()
	res := &model.Result{Server: sv, CycleID: cycleID, Collected: start.UTC()}
	defer func() {
		res.Duration = time.Since(start)
		c.o.Metrics.ServerDuration.Observe(res.Duration.Seconds())
		if res.Err != "" && res.Vendor == "" {
			res.Vendor = strings.ToLower(sv.Vendor)
			if res.Vendor == "" {
				res.Vendor = "unknown"
			}
		}
	}()

	ref, err := c.o.Vault.Resolve(sv.SecretRef)
	if err != nil {
		res.Err = ErrCredentialFailed + ": " + err.Error()
		return res
	}
	cred, err := c.o.Vault.Get(ctx, ref)
	if err != nil {
		res.Err = ErrCredentialPending + ": " + err.Error()
		return res
	}
	if c.authBlocked(sv.ID, cred.Version) {
		res.Err = ErrCredentialFailed + ": BMC rejected this secret, waiting for rotation or retry window"
		return res
	}

	addr := sv.BMCAddr
	if !strings.HasPrefix(addr, "http") {
		addr = "https://" + addr
	}
	target := redfish.Target{BaseURL: addr, Username: cred.Username, Password: cred.Password}
	br := c.breaker(sv.BMCAddr, cfg)

	accept := func(r *model.Result) {
		res.Vendor, res.Model, res.CPUModel = r.Vendor, r.Model, r.CPUModel
		res.Samples, res.Families = r.Samples, r.Families
		c.authFail.Delete(sv.ID)
	}

	_, err = br.Execute(func() (struct{}, error) {
		var last error
		for attempt := 0; attempt <= cfg.Collect.Retries; attempt++ {
			if attempt > 0 {
				select {
				case <-time.After(time.Duration(1<<uint(attempt-1)) * time.Second):
				case <-ctx.Done():
					return struct{}{}, ctx.Err()
				}
			}
			cctx, cancel := context.WithTimeout(ctx, cfg.Collect.Timeout)
			r, err := c.collectSession(cctx, target, sv, families)
			cancel()
			if err == nil {
				accept(r)
				return struct{}{}, nil
			}
			last = err
			if !errors.Is(err, redfish.ErrUnauthorized) {
				continue
			}
			// Rejected password: the secret may have been rotated. Ask the vault
			// for a fresh one and retry once, but only with a genuinely different
			// secret; resending the same one just burns the BMC's lockout counter.
			c.o.Metrics.VaultAuthFail.Inc()
			c.o.Vault.Invalidate(ref, cred.Version)
			fresh, gerr := c.o.Vault.Get(ctx, ref)
			if gerr != nil || fresh.Version == cred.Version {
				c.noteAuthFail(sv.ID, cred.Version)
				break
			}
			c.o.Metrics.VaultRotations.Inc()
			cred = fresh
			target.Username, target.Password = fresh.Username, fresh.Password
			cctx, cancel = context.WithTimeout(ctx, cfg.Collect.Timeout)
			r, err = c.collectSession(cctx, target, sv, families)
			cancel()
			if err == nil {
				accept(r)
				return struct{}{}, nil
			}
			last = err
			if errors.Is(err, redfish.ErrUnauthorized) {
				c.o.Metrics.VaultAuthFail.Inc()
				c.noteAuthFail(sv.ID, fresh.Version)
			}
			break
		}
		return struct{}{}, last
	})
	if err != nil {
		res.Err = err.Error()
	}
	return res
}

func (c *Collector) authRetryWindow() time.Duration {
	if c.o.AuthRetry > 0 {
		return c.o.AuthRetry
	}
	return 30 * time.Minute
}

func (c *Collector) noteAuthFail(id string, version uint64) {
	c.authFail.Store(id, authFailure{version: version, at: time.Now()})
}

// authBlocked reports whether the BMC already rejected exactly this secret
// version less than the retry window ago.
func (c *Collector) authBlocked(id string, version uint64) bool {
	v, ok := c.authFail.Load(id)
	if !ok {
		return false
	}
	f := v.(authFailure)
	return f.version == version && time.Since(f.at) < c.authRetryWindow()
}

func (c *Collector) collectSession(ctx context.Context, t redfish.Target, sv model.Server, families []model.Family) (*model.Result, error) {
	s, err := c.client.Open(ctx, t)
	if err != nil {
		return nil, err
	}
	manu := sv.Vendor
	if manu == "" {
		manu = s.Manufacturer()
	}
	adapter := c.o.Registry.Resolve(manu)
	r := redfish.Collect(ctx, s, adapter, families)
	r.Vendor = adapter.Vendor()
	return r, nil
}

func enabledFamilies(cfg *config.Central) []model.Family {
	var out []model.Family
	for _, f := range []model.Family{model.FamilyCPU, model.FamilyMemory, model.FamilyThermal, model.FamilyPower} {
		if cfg.MetricEnabled(string(f)) {
			out = append(out, f)
		}
	}
	return out
}
