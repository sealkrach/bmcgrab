-- bmcgrab initial schema (TimescaleDB >= 2.11, PostgreSQL >= 14)
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Raw samples. One row per sensor reading. Partitioned by time.
CREATE TABLE IF NOT EXISTS metrics (
    time        TIMESTAMPTZ      NOT NULL,
    server_id   TEXT             NOT NULL,
    hostname    TEXT             NOT NULL,
    region      TEXT             NOT NULL,
    vendor      TEXT             NOT NULL,
    family      TEXT             NOT NULL,   -- cpu | memory | thermal | power
    name        TEXT             NOT NULL,   -- cpu_usage_percent, temperature_c, ...
    sensor      TEXT             NOT NULL DEFAULT '',
    value       DOUBLE PRECISION NOT NULL,
    unit        TEXT             NOT NULL,
    cycle_id    TEXT             NOT NULL
);
SELECT create_hypertable('metrics', 'time', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS metrics_server_time_idx ON metrics (server_id, time DESC);
CREATE INDEX IF NOT EXISTS metrics_region_name_time_idx ON metrics (region, name, time DESC);

ALTER TABLE metrics SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'server_id, name',
    timescaledb.compress_orderby   = 'time DESC'
);
SELECT add_compression_policy('metrics', INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_retention_policy('metrics', INTERVAL '90 days', if_not_exists => TRUE);

-- Per-server, per-cycle outcome: this is the data-quality guarantee.
CREATE TABLE IF NOT EXISTS collection_status (
    time        TIMESTAMPTZ NOT NULL,
    cycle_id    TEXT        NOT NULL,
    server_id   TEXT        NOT NULL,
    hostname    TEXT        NOT NULL,
    region      TEXT        NOT NULL,
    vendor      TEXT        NOT NULL,
    model       TEXT        NOT NULL DEFAULT '',
    cpu_model   TEXT        NOT NULL DEFAULT '',
    status      TEXT        NOT NULL,          -- ok | partial | failed
    duration_ms INTEGER     NOT NULL,
    families    JSONB       NOT NULL,          -- [{family,state,reason,samples}]
    error       TEXT        NOT NULL DEFAULT ''
);
SELECT create_hypertable('collection_status', 'time', chunk_time_interval => INTERVAL '7 days', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS collection_status_server_idx ON collection_status (server_id, time DESC);
CREATE INDEX IF NOT EXISTS collection_status_region_idx ON collection_status (region, time DESC);
SELECT add_retention_policy('collection_status', INTERVAL '90 days', if_not_exists => TRUE);

-- Latest status per server (fast for the UI).
CREATE TABLE IF NOT EXISTS server_state (
    server_id   TEXT PRIMARY KEY,
    hostname    TEXT        NOT NULL,
    region      TEXT        NOT NULL,
    vendor      TEXT        NOT NULL,
    model       TEXT        NOT NULL DEFAULT '',
    cpu_model   TEXT        NOT NULL DEFAULT '',
    status      TEXT        NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL,
    last_ok     TIMESTAMPTZ,
    families    JSONB       NOT NULL,
    error       TEXT        NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS server_state_region_status_idx ON server_state (region, status);

-- One row per collector instance per cycle.
CREATE TABLE IF NOT EXISTS collector_heartbeat (
    region          TEXT        NOT NULL,
    instance        TEXT        NOT NULL,       -- hostname of the collector
    time            TIMESTAMPTZ NOT NULL,
    cycle_id        TEXT        NOT NULL,
    version         TEXT        NOT NULL,
    config_version  INTEGER     NOT NULL,
    servers         INTEGER     NOT NULL,
    ok              INTEGER     NOT NULL,
    partial         INTEGER     NOT NULL,
    failed          INTEGER     NOT NULL,
    breaker_open    INTEGER     NOT NULL,
    rejected        INTEGER     NOT NULL,
    buffered        BIGINT      NOT NULL,       -- bytes waiting in local buffer
    duration_ms     INTEGER     NOT NULL,
    inventory_error TEXT        NOT NULL DEFAULT '',
    PRIMARY KEY (region, instance, time)
);
-- Small table; the server prunes rows older than 30 days on startup.

-- Central configuration, versioned; the highest version is current.
CREATE TABLE IF NOT EXISTS config (
    version     SERIAL PRIMARY KEY,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    author      TEXT        NOT NULL,
    document    JSONB       NOT NULL
);

-- Audit of every UI action.
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    time        TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor       TEXT        NOT NULL,
    action      TEXT        NOT NULL,
    details     JSONB       NOT NULL DEFAULT '{}'::jsonb
);

-- Continuous aggregate: hourly per server & metric, kept 2 years.
CREATE MATERIALIZED VIEW IF NOT EXISTS metrics_1h
WITH (timescaledb.continuous) AS
SELECT time_bucket('1 hour', time) AS bucket,
       server_id, hostname, region, vendor, name,
       avg(value) AS avg_value, min(value) AS min_value, max(value) AS max_value,
       count(*)   AS samples
FROM metrics
GROUP BY bucket, server_id, hostname, region, vendor, name
WITH NO DATA;
SELECT add_continuous_aggregate_policy('metrics_1h',
    start_offset => INTERVAL '3 days', end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour', if_not_exists => TRUE);
SELECT add_retention_policy('metrics_1h', INTERVAL '2 years', if_not_exists => TRUE);

-- Least-privilege roles (create users separately; passwords are not in SQL).
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bmcgrab_writer') THEN
        CREATE ROLE bmcgrab_writer NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bmcgrab_server') THEN
        CREATE ROLE bmcgrab_server NOLOGIN;
    END IF;
END $$;
GRANT INSERT ON metrics, collection_status, collector_heartbeat TO bmcgrab_writer;
GRANT INSERT, UPDATE ON server_state TO bmcgrab_writer;
GRANT SELECT ON config TO bmcgrab_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO bmcgrab_server;
GRANT INSERT ON config, audit_log TO bmcgrab_server;
GRANT USAGE ON SEQUENCE config_version_seq, audit_log_id_seq TO bmcgrab_server;
