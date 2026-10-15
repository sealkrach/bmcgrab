package timescale

import (
	"context"
	"encoding/json"
	"time"

	"github.com/sealkrach/bmcgrab/internal/model"
)

// RegionSummary is one row of the dashboard's region table.
type RegionSummary struct {
	Region       string
	Instance     string
	LastCycle    time.Time
	Servers      int
	OK, Partial  int
	Failed       int
	BreakerOpen  int
	Buffered     int64
	Duration     time.Duration
	InventoryErr string
	Stale        bool // no heartbeat in > 2 intervals
}

// Regions returns the latest heartbeat per region.
func (s *Store) Regions(ctx context.Context, staleAfter time.Duration) ([]RegionSummary, error) {
	rows, err := s.pool.Query(ctx, `
	  SELECT DISTINCT ON (region) region, instance, time, servers, ok, partial, failed, breaker_open, buffered, duration_ms, inventory_error
	  FROM collector_heartbeat ORDER BY region, time DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RegionSummary
	for rows.Next() {
		var r RegionSummary
		var ms int32
		if err := rows.Scan(&r.Region, &r.Instance, &r.LastCycle, &r.Servers, &r.OK, &r.Partial, &r.Failed, &r.BreakerOpen, &r.Buffered, &ms, &r.InventoryErr); err != nil {
			return nil, err
		}
		r.Duration = time.Duration(ms) * time.Millisecond
		r.Stale = time.Since(r.LastCycle) > staleAfter
		out = append(out, r)
	}
	return out, rows.Err()
}

// Totals counts servers by current status.
type Totals struct{ OK, Partial, Failed, Total int }

// Totals aggregates server_state.
func (s *Store) Totals(ctx context.Context) (Totals, error) {
	var t Totals
	err := s.pool.QueryRow(ctx, `
	  SELECT count(*) FILTER (WHERE status='ok'), count(*) FILTER (WHERE status='partial'),
	         count(*) FILTER (WHERE status='failed'), count(*) FROM server_state`).
		Scan(&t.OK, &t.Partial, &t.Failed, &t.Total)
	return t, err
}

// ServerRow is one line of the servers list.
type ServerRow struct {
	ID, Hostname, Region, Vendor, Model string
	Status                              string
	LastSeen                            time.Time
	LastOK                              *time.Time
	Families                            []model.FamilyResult
	Error                               string
}

// Servers lists server_state filtered by region/status/search (all optional).
func (s *Store) Servers(ctx context.Context, region, status, search string, limit int) ([]ServerRow, error) {
	rows, err := s.pool.Query(ctx, `
	  SELECT server_id, hostname, region, vendor, model, status, last_seen, last_ok, families, error
	  FROM server_state
	  WHERE ($1 = '' OR region = $1) AND ($2 = '' OR status = $2)
	    AND ($3 = '' OR hostname ILIKE '%' || $3 || '%' OR server_id ILIKE '%' || $3 || '%')
	  ORDER BY CASE status WHEN 'failed' THEN 0 WHEN 'partial' THEN 1 ELSE 2 END, hostname
	  LIMIT $4`, region, status, search, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServerRow
	for rows.Next() {
		var r ServerRow
		var fam []byte
		if err := rows.Scan(&r.ID, &r.Hostname, &r.Region, &r.Vendor, &r.Model, &r.Status, &r.LastSeen, &r.LastOK, &fam, &r.Error); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(fam, &r.Families)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Point is one aggregated value for charts.
type Point struct {
	Time  time.Time `json:"t"`
	Value float64   `json:"v"`
}

// Trend returns the region-wide average of a metric over the last window,
// bucketed to keep the series small.
func (s *Store) Trend(ctx context.Context, region, name string, window, bucket time.Duration) ([]Point, error) {
	rows, err := s.pool.Query(ctx, `
	  SELECT time_bucket($4::interval, time) AS b, avg(value)
	  FROM metrics WHERE name = $2 AND time > now() - $3::interval AND ($1 = '' OR region = $1)
	  GROUP BY b ORDER BY b`, region, name, window.String(), bucket.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Point
	for rows.Next() {
		var p Point
		if err := rows.Scan(&p.Time, &p.Value); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UnsupportedByVendor counts how many servers report each family unsupported,
// so the operator sees at a glance what the fleet cannot give.
func (s *Store) UnsupportedByVendor(ctx context.Context) (map[string]map[string]int, error) {
	rows, err := s.pool.Query(ctx, `
	  SELECT vendor, f->>'family', count(*) FROM server_state, jsonb_array_elements(families) f
	  WHERE f->>'state' = 'unsupported' GROUP BY 1, 2`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]int{}
	for rows.Next() {
		var v, f string
		var n int
		if err := rows.Scan(&v, &f, &n); err != nil {
			return nil, err
		}
		if out[v] == nil {
			out[v] = map[string]int{}
		}
		out[v][f] = n
	}
	return out, rows.Err()
}

// PruneHeartbeats deletes heartbeats older than the given age.
func (s *Store) PruneHeartbeats(ctx context.Context, olderThan time.Duration) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM collector_heartbeat WHERE time < now() - $1::interval`, olderThan.String())
	return err
}
