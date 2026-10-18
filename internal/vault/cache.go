package vault

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Mode selects how a server is mapped onto a CyberArk account.
type Mode string

const (
	ModeShared   Mode = "shared"    // one account for every BMC; secret_ref is ignored
	ModePerAsset Mode = "per_asset" // every BMC must carry its own secret_ref
	ModeAuto     Mode = "auto"      // secret_ref when present, else the shared account
)

// Hooks let the caller count events without this package knowing about
// metrics. Any field may be nil.
type Hooks struct {
	OnFetch func(ok bool) // one call per vault request
	OnStale func()        // a stale secret was served because the vault failed
}

// CacheConfig tunes the cache. Zero values get sensible defaults.
type CacheConfig struct {
	Mode          Mode
	Default       Ref           // shared account / default Safe
	TTL           time.Duration // default 1h
	StaleMax      time.Duration // how long past expiry a secret may be served if the vault is down (default 6h)
	RefreshAhead  float64       // fraction of TTL after which Refresh(force=false) refetches (default 0.8)
	Jitter        float64       // ± fraction applied to each TTL (default 0.1)
	MaxConcurrent int           // concurrent vault requests (default 8)
	MinRefetch    time.Duration // Invalidate ignores secrets fetched more recently than this (default 30s)
	FailBackoff   time.Duration // after a failed fetch, serve the error without retrying for this long (default 30s)
	Store         Store         // default PlainStore
	Hooks         Hooks
	Now           func() time.Time // tests
}

type entry struct {
	user      string
	secret    Secret
	version   uint64
	fetchedAt time.Time
	expiresAt time.Time
	bad       bool      // rejected by a BMC: never serve it as stale
	errUntil  time.Time // no new vault request before this time
	lastErr   error
}

// Cache is a Provider that caches one secret per account in front of a Fetcher.
type Cache struct {
	f   Fetcher
	cfg CacheConfig

	mu      sync.Mutex
	entries map[Ref]*entry
	nextVer uint64

	flight singleflight.Group
	sem    chan struct{}
}

// NewCache wraps f.
func NewCache(f Fetcher, cfg CacheConfig) *Cache {
	if cfg.Mode == "" {
		cfg.Mode = ModeAuto
	}
	if cfg.TTL <= 0 {
		cfg.TTL = time.Hour
	}
	if cfg.StaleMax <= 0 {
		cfg.StaleMax = 6 * time.Hour
	}
	if cfg.RefreshAhead <= 0 || cfg.RefreshAhead > 1 {
		cfg.RefreshAhead = 0.8
	}
	if cfg.Jitter < 0 || cfg.Jitter >= 1 {
		cfg.Jitter = 0.1
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 8
	}
	if cfg.MinRefetch <= 0 {
		cfg.MinRefetch = 30 * time.Second
	}
	if cfg.FailBackoff <= 0 {
		cfg.FailBackoff = 30 * time.Second
	}
	if cfg.Store == nil {
		cfg.Store = PlainStore()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Cache{f: f, cfg: cfg, entries: map[Ref]*entry{}, sem: make(chan struct{}, cfg.MaxConcurrent)}
}

func (c *Cache) Name() string { return c.f.Name() + " (cache:" + c.cfg.Store.Name() + ")" }

func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, e := range c.entries {
		if e.secret != nil {
			n++
		}
	}
	return Stats{Entries: n}
}

// normalize fills a partial reference from the default account.
func (c *Cache) normalize(r Ref) Ref {
	if r.IsZero() {
		return c.cfg.Default
	}
	if r.Safe == "" {
		r.Safe = c.cfg.Default.Safe
	}
	return r
}

func (c *Cache) Resolve(secretRef string) (Ref, error) {
	if c.cfg.Mode == ModeShared {
		return c.normalize(Ref{}), nil
	}
	r, err := ParseRef(secretRef)
	if err != nil {
		return Ref{}, err
	}
	if r.IsZero() {
		if c.cfg.Mode == ModePerAsset {
			return Ref{}, errors.New("per_asset mode: server has no secret_ref")
		}
		return c.normalize(Ref{}), nil
	}
	if r.Safe == "" {
		r.Safe = c.cfg.Default.Safe
	}
	if r.Safe == "" {
		return Ref{}, fmt.Errorf("secret_ref %q has no Safe and no default Safe is configured", r.Object)
	}
	return r, nil
}

func (c *Cache) ttl() time.Duration {
	j := 1 + (rand.Float64()*2-1)*c.cfg.Jitter
	return time.Duration(float64(c.cfg.TTL) * j)
}

func cred(e *entry) Credential {
	return Credential{Username: e.user, Password: e.secret.Reveal(), Version: e.version}
}

// staleOK reports whether e may be served although it is expired. Caller holds mu.
func (c *Cache) staleOK(e *entry, now time.Time) bool {
	return e != nil && e.secret != nil && !e.bad && now.Before(e.expiresAt.Add(c.cfg.StaleMax))
}

func (c *Cache) Get(ctx context.Context, ref Ref) (Credential, error) {
	ref = c.normalize(ref)
	now := c.cfg.Now()
	c.mu.Lock()
	e := c.entries[ref]
	if e != nil && e.secret != nil && !e.bad && now.Before(e.expiresAt) {
		out := cred(e)
		c.mu.Unlock()
		return out, nil
	}
	if e != nil && now.Before(e.errUntil) {
		// The vault failed a moment ago: do not hammer it.
		out, err := c.serveStaleLocked(e, now, e.lastErr)
		c.mu.Unlock()
		return out, err
	}
	c.mu.Unlock()

	v, err, _ := c.flight.Do(ref.String(), func() (any, error) {
		return c.fetch(context.WithoutCancel(ctx), ref, false)
	})
	if err != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.serveStaleLocked(c.entries[ref], c.cfg.Now(), err)
	}
	return v.(Credential), nil
}

// serveStaleLocked returns e if it may be served stale, else err.
func (c *Cache) serveStaleLocked(e *entry, now time.Time, err error) (Credential, error) {
	if c.staleOK(e, now) {
		if c.cfg.Hooks.OnStale != nil {
			c.cfg.Hooks.OnStale()
		}
		return cred(e), nil
	}
	if err == nil {
		err = errors.New("no credential available")
	}
	return Credential{}, err
}

// fetch performs one vault request (bounded by the semaphore) and stores the
// result. Unless force is set it first re-checks freshness, so waiters queued
// behind another fetch of the same account do not repeat it.
func (c *Cache) fetch(ctx context.Context, ref Ref, force bool) (Credential, error) {
	if !force {
		c.mu.Lock()
		if e := c.entries[ref]; e != nil && e.secret != nil && !e.bad && c.cfg.Now().Before(e.expiresAt) {
			out := cred(e)
			c.mu.Unlock()
			return out, nil
		}
		c.mu.Unlock()
	}
	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	case <-ctx.Done():
		return Credential{}, ctx.Err()
	}
	fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	got, err := c.f.Fetch(fctx, ref)
	now := c.cfg.Now()
	if c.cfg.Hooks.OnFetch != nil {
		c.cfg.Hooks.OnFetch(err == nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[ref]
	if err != nil {
		if e == nil {
			e = &entry{}
			c.entries[ref] = e
		}
		e.errUntil, e.lastErr = now.Add(c.cfg.FailBackoff), err
		return Credential{}, err
	}
	if e == nil {
		e = &entry{}
		c.entries[ref] = e
	}
	changed := e.secret == nil || subtle.ConstantTimeCompare([]byte(e.secret.Reveal()), []byte(got.Password)) != 1
	if changed {
		sealed, serr := c.cfg.Store.Seal(got.Password)
		if serr != nil {
			e.errUntil, e.lastErr = now.Add(c.cfg.FailBackoff), serr
			return Credential{}, fmt.Errorf("seal secret: %w", serr)
		}
		if e.secret != nil {
			e.secret.Destroy()
		}
		c.nextVer++
		e.secret, e.version = sealed, c.nextVer
	}
	e.user, e.fetchedAt, e.expiresAt = got.Username, now, now.Add(c.ttl())
	e.bad, e.errUntil, e.lastErr = false, time.Time{}, nil
	out := cred(e)
	out.Version = e.version
	return out, nil
}

func (c *Cache) Invalidate(ref Ref, version uint64) {
	ref = c.normalize(ref)
	now := c.cfg.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[ref]
	if e == nil || e.secret == nil || e.version != version {
		return // already replaced by a newer secret
	}
	if now.Sub(e.fetchedAt) < c.cfg.MinRefetch {
		return // just fetched: a BMC-side problem, not a stale secret
	}
	e.bad, e.expiresAt, e.errUntil = true, time.Time{}, time.Time{}
}

func (c *Cache) Refresh(ctx context.Context, refs []Ref, force bool) Report {
	seen := map[Ref]bool{}
	var todo []Ref
	rep := Report{}
	now := c.cfg.Now()
	for _, r := range refs {
		r = c.normalize(r)
		if seen[r] {
			continue
		}
		seen[r] = true
		rep.Requested++
		if !force && !c.due(r, now) {
			rep.Skipped++
			continue
		}
		todo = append(todo, r)
	}

	type outcome struct {
		ref     Ref
		changed bool
		err     error
	}
	jobs := make(chan Ref)
	out := make(chan outcome)
	var wg sync.WaitGroup
	for i := 0; i < c.cfg.MaxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range jobs {
				c.mu.Lock()
				var before uint64
				if e := c.entries[r]; e != nil {
					before = e.version
				}
				c.mu.Unlock()
				v, err, _ := c.flight.Do(r.String(), func() (any, error) { return c.fetch(ctx, r, true) })
				o := outcome{ref: r, err: err}
				if err == nil {
					o.changed = before != 0 && v.(Credential).Version != before
				}
				out <- o
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, r := range todo {
			select {
			case jobs <- r:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(out) }()
	for o := range out {
		if o.err != nil {
			rep.Failed++
			rep.Errors = append(rep.Errors, RefError{Ref: o.ref.String(), Err: o.err.Error()})
			continue
		}
		rep.Fetched++
		if o.changed {
			rep.Changed++
		}
	}
	// Anything neither fetched nor failed was cut short by ctx.
	if rest := len(todo) - rep.Fetched - rep.Failed; rest > 0 {
		rep.Skipped += rest
	}
	return rep
}

// due reports whether r is missing, rejected or past RefreshAhead of its TTL.
func (c *Cache) due(r Ref, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[r]
	if e == nil || e.secret == nil || e.bad {
		return true
	}
	life := e.expiresAt.Sub(e.fetchedAt)
	return now.After(e.fetchedAt.Add(time.Duration(float64(life) * c.cfg.RefreshAhead)))
}
