// Package timescale writes samples and statuses to TimescaleDB with COPY, and
// reads the central configuration. It also exposes the read queries used by
// the server mode.
package timescale

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sealkrach/bmcgrab/internal/config"
	"github.com/sealkrach/bmcgrab/internal/model"
)

// Store wraps a pgx pool.
type Store struct{ pool *pgxpool.Pool }

// Open connects with a small pool (collectors write in bursts).
func Open(ctx context.Context, dsn string, maxConns int32) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	cfg.MaxConnLifetime = time.Hour
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Ping checks connectivity.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Pool exposes the pool for read queries in server mode.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// ----------------------------------------------------------------- migrate

// Migrations lists the embedded SQL files in order. Set from main via
// SetMigrations because the files live at the repo root.
var migrationsFS fs.FS

// SetMigrations registers the embedded migrations filesystem.
func SetMigrations(f embed.FS) { migrationsFS = f }

// Migrate applies every migrations/*.sql not yet recorded in schema_migrations.
func (s *Store) Migrate(ctx context.Context) ([]string, error) {
	if migrationsFS == nil {
		return nil, errors.New("migrations not registered")
	}
	if _, err := s.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var applied []string
	for _, n := range names {
		var exists bool
		if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name=$1)`, n).Scan(&exists); err != nil {
			return applied, err
		}
		if exists {
			continue
		}
		sqlb, err := fs.ReadFile(migrationsFS, "migrations/"+n)
		if err != nil {
			return applied, err
		}
		if _, err := s.pool.Exec(ctx, string(sqlb)); err != nil {
			return applied, fmt.Errorf("migration %s: %w", n, err)
		}
		if _, err := s.pool.Exec(ctx, `INSERT INTO schema_migrations(name) VALUES($1)`, n); err != nil {
			return applied, err
		}
		applied = append(applied, n)
	}
	// Seed default config if the table is empty.
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM config`).Scan(&n); err == nil && n == 0 {
		if _, err := s.SaveConfig(ctx, config.Default(), "migrate"); err != nil {
			return applied, err
		}
	}
	return applied, nil
}

// ------------------------------------------------------------------ config

// LoadConfig returns the latest central config.
func (s *Store) LoadConfig(ctx context.Context) (*config.Central, error) {
	var version int
	var updated time.Time
	var author string
	var doc []byte
	err := s.pool.QueryRow(ctx, `SELECT version, updated_at, author, document FROM config ORDER BY version DESC LIMIT 1`).
		Scan(&version, &updated, &author, &doc)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	var c config.Central
	if err := json.Unmarshal(doc, &c); err != nil {
		return nil, fmt.Errorf("parse config v%d: %w", version, err)
	}
	c.Version, c.Updated, c.Author = version, updated, author
	return &c, nil
}

// SaveConfig inserts a new version and returns it.
func (s *Store) SaveConfig(ctx context.Context, c *config.Central, author string) (int, error) {
	if err := c.Validate(); err != nil {
		return 0, err
	}
	doc, err := json.Marshal(c)
	if err != nil {
		return 0, err
	}
	var v int
	err = s.pool.QueryRow(ctx, `INSERT INTO config(author, document) VALUES($1, $2) RETURNING version`, author, doc).Scan(&v)
	return v, err
}

// ConfigHistory lists past versions (newest first).
func (s *Store) ConfigHistory(ctx context.Context, limit int) ([]config.Central, error) {
	rows, err := s.pool.Query(ctx, `SELECT version, updated_at, author, document FROM config ORDER BY version DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []config.Central
	for rows.Next() {
		var c config.Central
		var doc []byte
		if err := rows.Scan(&c.Version, &c.Updated, &c.Author, &doc); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(doc, &c)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ------------------------------------------------------------------- write

// Batch is one cycle's worth of results ready to COPY.
type Batch struct {
	Results []*model.Result
}

// WriteResults COPYs samples and statuses and upserts server_state, all in
// one transaction so a cycle is either fully recorded or not at all.
func (s *Store) WriteResults(ctx context.Context, results []*model.Result) error {
	if len(results) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// metrics
	rows := make([][]any, 0, len(results)*16)
	for _, r := range results {
		for _, smp := range r.Samples {
			rows = append(rows, []any{smp.Time, r.Server.ID, r.Server.Hostname, r.Server.Region, r.Vendor,
				string(smp.Family), smp.Name, smp.Sensor, smp.Value, smp.Unit, r.CycleID})
		}
	}
	if len(rows) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"metrics"},
			[]string{"time", "server_id", "hostname", "region", "vendor", "family", "name", "sensor", "value", "unit", "cycle_id"},
			pgx.CopyFromRows(rows)); err != nil {
			return fmt.Errorf("copy metrics: %w", err)
		}
	}

	// collection_status
	st := make([][]any, 0, len(results))
	for _, r := range results {
		fam, _ := json.Marshal(r.Families)
		st = append(st, []any{r.Collected, r.CycleID, r.Server.ID, r.Server.Hostname, r.Server.Region, r.Vendor,
			r.Model, r.CPUModel, r.Status(), int32(r.Duration.Milliseconds()), fam, r.Err})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"collection_status"},
		[]string{"time", "cycle_id", "server_id", "hostname", "region", "vendor", "model", "cpu_model", "status", "duration_ms", "families", "error"},
		pgx.CopyFromRows(st)); err != nil {
		return fmt.Errorf("copy collection_status: %w", err)
	}

	// server_state upsert
	b := &pgx.Batch{}
	for _, r := range results {
		fam, _ := json.Marshal(r.Families)
		status := r.Status()
		var lastOK *time.Time
		if status == "ok" {
			t := r.Collected
			lastOK = &t
		}
		b.Queue(`INSERT INTO server_state(server_id, hostname, region, vendor, model, cpu_model, status, last_seen, last_ok, families, error)
		         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		         ON CONFLICT (server_id) DO UPDATE SET hostname=EXCLUDED.hostname, region=EXCLUDED.region, vendor=EXCLUDED.vendor,
		           model=EXCLUDED.model, cpu_model=EXCLUDED.cpu_model, status=EXCLUDED.status, last_seen=EXCLUDED.last_seen,
		           last_ok=COALESCE(EXCLUDED.last_ok, server_state.last_ok), families=EXCLUDED.families, error=EXCLUDED.error`,
			r.Server.ID, r.Server.Hostname, r.Server.Region, r.Vendor, r.Model, r.CPUModel, status, r.Collected, lastOK, fam, r.Err)
	}
	br := tx.SendBatch(ctx, b)
	for range results {
		if _, err := br.Exec(); err != nil {
			br.Close()
			return fmt.Errorf("upsert server_state: %w", err)
		}
	}
	if err := br.Close(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Heartbeat is one collector cycle summary.
type Heartbeat struct {
	Region, Instance, CycleID, Version string
	Time                               time.Time
	ConfigVersion                      int
	Servers, OK, Partial, Failed       int
	BreakerOpen, Rejected              int
	Buffered                           int64
	Duration                           time.Duration
	InventoryError                     string
}

// WriteHeartbeat records a cycle summary.
func (s *Store) WriteHeartbeat(ctx context.Context, h Heartbeat) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO collector_heartbeat
	  (region, instance, time, cycle_id, version, config_version, servers, ok, partial, failed, breaker_open, rejected, buffered, duration_ms, inventory_error)
	  VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		h.Region, h.Instance, h.Time, h.CycleID, h.Version, h.ConfigVersion, h.Servers, h.OK, h.Partial, h.Failed,
		h.BreakerOpen, h.Rejected, h.Buffered, int32(h.Duration.Milliseconds()), h.InventoryError)
	return err
}

// Audit records a UI action.
func (s *Store) Audit(ctx context.Context, actor, action string, details any) error {
	d, _ := json.Marshal(details)
	_, err := s.pool.Exec(ctx, `INSERT INTO audit_log(actor, action, details) VALUES($1,$2,$3)`, actor, action, d)
	return err
}
