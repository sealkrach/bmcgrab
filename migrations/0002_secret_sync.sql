-- Manual secret synchronisation: the server queues a request, every matching
-- collector claims it (one row per region in secret_sync_run), refreshes its
-- secret cache and records the outcome. No secret value is ever stored here.

CREATE TABLE IF NOT EXISTS secret_sync_request (
    id           BIGSERIAL   PRIMARY KEY,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    requested_by TEXT        NOT NULL,
    region       TEXT        NOT NULL DEFAULT '',   -- '' = every region
    server_id    TEXT        NOT NULL DEFAULT ''    -- '' = every server of the region
);
CREATE INDEX IF NOT EXISTS secret_sync_request_at ON secret_sync_request (requested_at DESC);

CREATE TABLE IF NOT EXISTS secret_sync_run (
    request_id  BIGINT      NOT NULL REFERENCES secret_sync_request(id) ON DELETE CASCADE,
    region      TEXT        NOT NULL,
    instance    TEXT        NOT NULL,
    status      TEXT        NOT NULL DEFAULT 'running',  -- running | done | failed
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    report      JSONB       NOT NULL DEFAULT '{}'::jsonb, -- counts and failed account refs, no secrets
    PRIMARY KEY (request_id, region)
);

GRANT SELECT ON secret_sync_request, secret_sync_run TO bmcgrab_server;
GRANT INSERT ON secret_sync_request TO bmcgrab_server;
GRANT USAGE ON SEQUENCE secret_sync_request_id_seq TO bmcgrab_server;
GRANT SELECT ON secret_sync_request TO bmcgrab_writer;
GRANT SELECT, INSERT, UPDATE ON secret_sync_run TO bmcgrab_writer;
