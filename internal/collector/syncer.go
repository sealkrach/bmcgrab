package collector

import (
	"context"
	"time"

	"github.com/sealkrach/bmcgrab/internal/vault"
)

// SyncSecrets refreshes the cached secrets of every server in the region.
// With force every account is refetched; otherwise only those missing or past
// their refresh-ahead point. It runs outside the collection cycle, so a slow
// or failing vault never delays a cycle.
func (c *Collector) SyncSecrets(ctx context.Context, force bool, serverID string) (vault.Report, error) {
	c.mu.Lock()
	cfg := c.central
	c.mu.Unlock()
	if cfg == nil {
		cfg = c.loadConfig(ctx)
	}
	if err := c.ensureDeps(cfg); err != nil {
		return vault.Report{}, err
	}
	servers, err := c.inv.List(ctx, c.o.Local.Region)
	if err != nil {
		return vault.Report{}, err
	}
	seen := map[vault.Ref]bool{}
	var refs []vault.Ref
	for _, sv := range servers {
		if serverID != "" && sv.ID != serverID {
			continue
		}
		ref, err := c.o.Vault.Resolve(sv.SecretRef)
		if err != nil || seen[ref] {
			continue // the per-server error surfaces during collection
		}
		seen[ref] = true
		refs = append(refs, ref)
	}
	start := time.Now()
	rep := c.o.Vault.Refresh(ctx, refs, force)
	c.o.Metrics.VaultSyncDur.Observe(time.Since(start).Seconds())
	c.o.Metrics.VaultEntries.Set(float64(c.o.Vault.Stats().Entries))
	for i := 0; i < rep.Changed; i++ {
		c.o.Metrics.VaultRotations.Inc()
	}
	c.o.Log.Info("secret sync", "force", force, "server", serverID, "accounts", rep.Requested, "fetched", rep.Fetched,
		"rotated", rep.Changed, "skipped", rep.Skipped, "failed", rep.Failed)
	for _, e := range rep.Errors {
		c.o.Log.Warn("secret sync failed for account", "ref", e.Ref, "err", e.Err)
	}
	return rep, nil
}

// syncLoop keeps the secret cache warm and fresh in the background: an
// immediate pass at start (pre-warming), one per SyncInterval, and manual
// requests queued from the UI, polled every few seconds.
func (c *Collector) syncLoop(ctx context.Context) {
	var auto <-chan time.Time
	if c.o.SyncInterval > 0 {
		t := time.NewTicker(c.o.SyncInterval)
		defer t.Stop()
		auto = t.C
		c.autoSync(ctx)
	}
	var manual <-chan time.Time
	if c.o.Store != nil {
		t := time.NewTicker(manualPoll)
		defer t.Stop()
		manual = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-auto:
			c.autoSync(ctx)
		case <-manual:
			c.manualSync(ctx)
		}
	}
}

const (
	manualPoll   = 10 * time.Second
	manualWindow = 15 * time.Minute // older unclaimed requests are considered abandoned
)

func (c *Collector) autoSync(ctx context.Context) {
	if _, err := c.SyncSecrets(ctx, false, ""); err != nil && ctx.Err() == nil {
		c.o.Log.Warn("secret sync skipped", "err", err)
	}
}

// manualSync executes the requests queued for this region. A forced sync
// refetches every account, so a rotation done in the vault is picked up now.
func (c *Collector) manualSync(ctx context.Context) {
	region := c.o.Local.Region
	reqs, err := c.o.Store.ClaimSecretSync(ctx, region, c.instance, time.Now().Add(-manualWindow))
	if err != nil {
		if ctx.Err() == nil && err.Error() != c.lastPollErr {
			c.o.Log.Warn("secret sync requests unreadable (run `bmcgrab migrate`?)", "err", err)
		}
		c.lastPollErr = err.Error()
		return
	}
	c.lastPollErr = ""
	for _, q := range reqs {
		c.o.Log.Info("manual secret sync", "request", q.ID, "by", q.RequestedBy, "server", q.ServerID)
		rep, err := c.SyncSecrets(ctx, true, q.ServerID)
		status := "done"
		if err != nil || rep.Failed > 0 {
			status = "failed"
		}
		if err != nil {
			rep.Errors = append(rep.Errors, vault.RefError{Ref: "-", Err: err.Error()})
		}
		if ferr := c.o.Store.FinishSecretSync(ctx, q.ID, region, status, rep); ferr != nil {
			c.o.Log.Warn("secret sync result not recorded", "request", q.ID, "err", ferr)
		}
	}
}
