package timescale

import (
	"context"
	"encoding/json"
	"time"
)

// SecretSyncRequest is a manual "refresh the secrets" order queued by the UI.
type SecretSyncRequest struct {
	ID          int64
	RequestedAt time.Time
	RequestedBy string
	Region      string // "" = every region
	ServerID    string // "" = every server
}

// SecretSyncRun is one region's execution of a request.
type SecretSyncRun struct {
	RequestID   int64
	Region      string
	Instance    string
	Status      string
	StartedAt   time.Time
	FinishedAt  *time.Time
	Report      json.RawMessage
	RequestedBy string
	RequestedAt time.Time
	Scope       string
}

// RequestSecretSync queues a request and returns its id.
func (s *Store) RequestSecretSync(ctx context.Context, by, region, serverID string) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO secret_sync_request(requested_by, region, server_id) VALUES($1,$2,$3) RETURNING id`,
		by, region, serverID).Scan(&id)
	return id, err
}

// ClaimSecretSync returns the requests addressed to region that nobody of that
// region has taken yet, newest first limited to since, and claims each one for
// instance. A request is only returned to the instance that won the claim.
func (s *Store) ClaimSecretSync(ctx context.Context, region, instance string, since time.Time) ([]SecretSyncRequest, error) {
	rows, err := s.pool.Query(ctx, `
	  SELECT r.id, r.requested_at, r.requested_by, r.region, r.server_id
	  FROM secret_sync_request r
	  WHERE r.requested_at >= $2 AND (r.region = '' OR r.region = $1)
	    AND NOT EXISTS (SELECT 1 FROM secret_sync_run u WHERE u.request_id = r.id AND u.region = $1)
	  ORDER BY r.id`, region, since)
	if err != nil {
		return nil, err
	}
	var cand []SecretSyncRequest
	for rows.Next() {
		var q SecretSyncRequest
		if err := rows.Scan(&q.ID, &q.RequestedAt, &q.RequestedBy, &q.Region, &q.ServerID); err != nil {
			rows.Close()
			return nil, err
		}
		cand = append(cand, q)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var won []SecretSyncRequest
	for _, q := range cand {
		tag, err := s.pool.Exec(ctx,
			`INSERT INTO secret_sync_run(request_id, region, instance) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,
			q.ID, region, instance)
		if err != nil {
			return won, err
		}
		if tag.RowsAffected() == 1 {
			won = append(won, q)
		}
	}
	return won, nil
}

// FinishSecretSync records the outcome of a claimed request.
func (s *Store) FinishSecretSync(ctx context.Context, requestID int64, region, status string, report any) error {
	b, _ := json.Marshal(report)
	_, err := s.pool.Exec(ctx,
		`UPDATE secret_sync_run SET status=$3, finished_at=now(), report=$4 WHERE request_id=$1 AND region=$2`,
		requestID, region, status, b)
	return err
}

// SecretSyncRuns lists the latest runs for the UI.
func (s *Store) SecretSyncRuns(ctx context.Context, limit int) ([]SecretSyncRun, error) {
	rows, err := s.pool.Query(ctx, `
	  SELECT u.request_id, u.region, u.instance, u.status, u.started_at, u.finished_at, u.report,
	         r.requested_by, r.requested_at,
	         CASE WHEN r.server_id <> '' THEN 'server ' || r.server_id WHEN r.region <> '' THEN 'region ' || r.region ELSE 'all regions' END
	  FROM secret_sync_run u JOIN secret_sync_request r ON r.id = u.request_id
	  ORDER BY u.started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecretSyncRun
	for rows.Next() {
		var u SecretSyncRun
		if err := rows.Scan(&u.RequestID, &u.Region, &u.Instance, &u.Status, &u.StartedAt, &u.FinishedAt, &u.Report,
			&u.RequestedBy, &u.RequestedAt, &u.Scope); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
