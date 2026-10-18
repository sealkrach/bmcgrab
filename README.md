# bmcgrab

Multi-vendor Redfish telemetry collector for physical servers.
One static Go binary grabs **CPU usage, RAM usage, temperatures and power (watts)**
from the management controllers (iDRAC, iLO, XCC, Supermicro BMC, Bull) of
thousands of servers and writes them into **TimescaleDB** — with the BMC
credential pulled from **CyberArk**, an **external inventory** (SQL / REST / CSV),
and a central **web UI** to configure and watch everything.

Built for an operations team that should only ever have to: plug, configure, collect.

```
          Inventory (SQL/REST/CSV)     CyberArk CCP          5 000 BMCs (Redfish)
                    │                      │                        ▲
                    ▼                      ▼                        │
        ┌───────────────────────────────────────────────────────────┴──────┐
        │  bmcgrab collector  (one per region, stateless)                   │
        │  inventory cache → credential cache → worker pool → vendor        │
        │  adapters → quality validation → COPY to DB (or local buffer)     │
        └───────────────────────────────┬──────────────────────────────────┘
                                        ▼
                        TimescaleDB (metrics, status, config, heartbeat)
                                        ▲
                                        │ read + edit config
                        bmcgrab server (one instance: web UI, API, audit)
```

## What you get

| Concern | How bmcgrab handles it |
|---|---|
| Vendors | Dell iDRAC9, HPE iLO 5/6, Lenovo XCC, Supermicro, Bull/Eviden, plus a generic DMTF adapter. Detected from `Manufacturer`, overridable per server in the inventory. |
| CPU / RAM usage | Dell `TelemetryService/MetricReports/SystemUsage`, HPE `Oem.Hpe.SystemUsage`, Lenovo `Oem/Lenovo/Metrics`, otherwise a scan of percent sensors. When a BMC does not expose it, the family is reported **unsupported** with the reason (licence, firmware) — never guessed, never silently zero. |
| Data quality | Every reading is range-checked, unit-checked and timestamp-checked before insertion. Rejected readings are counted, logged and visible per server. Each server/cycle gets a status `ok / partial / failed` with per-family states `collected / unsupported / rejected / error`. |
| Secrets | CyberArk Central Credential Provider over mTLS; the secret lives only in memory, is never logged, is refreshed on a TTL and invalidated on 401. |
| Inventory | Never owned by bmcgrab: SQL (read-only query), REST (JSON path) or CSV, refreshed every cycle, cached locally for resilience. |
| Resilience | Per-BMC circuit breaker, retries with backoff, local NDJSON write-ahead buffer replayed when the database returns, config cache so collectors keep running without the DB. |
| Scale | Goroutine worker pool (default 50/collector), `COPY` batch inserts, TimescaleDB hypertable with compression after 7 days, 90-day raw retention, hourly continuous aggregate kept 2 years. |
| Multi-region | Same binary, `region:` in a 15-line YAML, one instance per region writing to one central DB. No orchestrator. |
| Configuration | Interval, workers, timeouts, breaker, metric families, quality ranges, inventory source: all in the DB, edited from the web UI, versioned with one-click rollback, applied at the next cycle without restart. |
| Observability | Prometheus `/metrics` and `/healthz` on every instance, JSON logs with a cycle id, heartbeat table per collector. |
| Security | Distroless non-root image, TLS verified against your CA (no skip outside `--lab`), least-privilege DB roles, OIDC SSO + audit log on the UI, CSP headers. |
| Pre-flight | `bmcgrab check` tests DB, config, CyberArk, inventory and a sample of BMCs and prints a green/red report. Also available as a page in the UI. |

## Quick start (lab)

```bash
make build                                   # bin/bmcgrab
BMCGRAB_BMC_USERNAME=admin BMCGRAB_BMC_PASSWORD=secret \
  docker compose -f deploy/docker/docker-compose.lab.yml up --build
# UI: http://localhost:8080  — collector metrics: http://localhost:9090/metrics
```

Edit `configs/inventory.example.csv` with real BMC addresses first, or switch the
inventory source to SQL/REST from the Configuration page.

## Production

1. **Database** — TimescaleDB ≥ 2.11. Create users for the roles `bmcgrab_writer`
   (collectors) and `bmcgrab_server` (UI), then `bmcgrab migrate --config server.yaml`.
2. **CyberArk** — a safe object holding the BMC read-only account, an AppID allowed
   for the collector hosts, and a client certificate. See `configs/collector.example.yaml`.
3. **Collectors** — one per region: `bmcgrab collector --config /etc/bmcgrab/collector.yaml`
   (systemd units in `deploy/systemd`, Helm chart in `deploy/helm/bmcgrab`).
4. **Server** — `bmcgrab server --config /etc/bmcgrab/server.yaml` behind your ingress,
   with an OIDC client on your identity provider.
5. **Check** — `bmcgrab check --config collector.yaml --sample 20` on each collector host.

Commands:

```
bmcgrab collector --config FILE          run the regional collector
bmcgrab server    --config FILE          run the central web UI / API
bmcgrab migrate   --config FILE          apply migrations, seed default config
bmcgrab check     --config FILE [--sample N] [--lab]
bmcgrab secrets sync   [--region R] [--server ID]   refetch BMC secrets from CyberArk now
bmcgrab secrets status                              latest synchronisations per region
```

## BMC credentials (CyberArk)

Two layouts, chosen with `cyberark.mode`:

* **shared** — one account for every BMC (`cyberark.safe` / `cyberark.object`).
* **per_asset** — each server has its own account: add a `secret_ref` column to the
  inventory (`safe/object`, or just `object` to reuse `cyberark.safe`). SQL inventory
  queries may return it as a sixth column. **auto** mixes both: `secret_ref` when set,
  otherwise the shared account.

Secrets are cached per account, in memory only (never on disk, never logged):

* One CCP request per account however many BMCs share it (single-flight), bounded by
  `max_concurrent`, TTL with jitter, and a short backoff after a CCP failure.
* An expired secret is served for up to `stale_max` if the CCP is down (metric
  `bmcgrab_vault_stale_served_total`), never one a BMC has rejected.
* **Rotation.** When a BMC answers 401 the account is re-read and the collection retried
  once, but only if the password actually changed. If the vault still returns the same
  password the BMC is left alone (`credential_failed`) until the secret changes or
  `auth_retry` elapses, so a rotation lag cannot lock BMC accounts.
* **Synchronisation** runs outside the collection cycle: at start (pre-warm), every
  `sync_interval`, and on demand from the UI (**Secrets** page) or
  `bmcgrab secrets sync`. Manual requests are queued in the database
  (`secret_sync_request`) and executed by the collectors of the targeted region within
  ~10 s; results are in `secret_sync_run`. A forced sync refetches every account.
* `secret_store: protected` keeps passwords in memguard enclaves: encrypted in RAM with
  the key in locked memory, excluded from core dumps and never swapped. It needs a small
  `RLIMIT_MEMLOCK` (systemd `LimitMEMLOCK=16M`); if unavailable the collector logs a
  warning and falls back to plain memory. This is not a hardware enclave (SGX/SEV/TDX):
  confidential-computing nodes would be the next step.

Every local YAML key can be overridden with `BMCGRAB_<SECTION>_<KEY>` environment variables.
`--lab` unlocks two things that must never be used in production: BMC credentials from
environment variables and `insecure_skip_verify` for BMC certificates.

## Data model

* `metrics` (hypertable) — `time, server_id, hostname, region, vendor, family, name, sensor, value, unit, cycle_id`.
  Names: `cpu_usage_percent`, `memory_usage_percent`, `temperature_c`, `power_w`.
* `collection_status` (hypertable) — one row per server per cycle with per-family states and reasons.
* `server_state` — latest status per server (what the UI lists).
* `collector_heartbeat` — one row per collector per cycle.
* `config` — versioned central configuration; `audit_log` — who changed what in the UI.
* `secret_sync_request` / `secret_sync_run` — manual secret synchronisations and their per-region outcome (no secret values).
* `metrics_1h` — continuous aggregate (avg/min/max per hour).

## Vendor notes (read before blaming the collector)

* **Dell**: `SystemUsage` needs the iDRAC **Datacenter** licence and telemetry enabled.
  Without it, CPU and memory are reported `unsupported` with that reason.
* **HPE**: `Oem.Hpe.SystemUsage` exists on iLO 5 ≥ 2.x and iLO 6. `MemoryBusUtil` is a bus
  utilisation, not RAM fill — stored under `memory_usage_percent` with sensor `memory_bus`.
* **Lenovo**: `Oem/Lenovo/Metrics` on recent XCC; older firmware exposes percent sensors instead.
* **Supermicro / Bull**: thermal and power only on most firmware; usage families show `unsupported`.
* The adapter layer lives in `internal/redfish/vendors/` — one small file per vendor.
  Adding a vendor = implementing four methods.

## Repository layout

```
cmd/bmcgrab            entrypoint: collector | server | check | migrate
internal/config        local YAML + central (DB) config
internal/vault         CyberArk CCP client, per-account secret cache, protected memory (+ env provider for labs)
internal/inventory     SQL / REST / CSV providers with cache
internal/redfish       raw Redfish client, adapter interface, standard helpers
internal/redfish/vendors  dell, hpe, lenovo, supermicro, bull, generic
internal/collector     scheduler, worker pool, breaker, retries
internal/quality       validation rules
internal/storage       timescale (COPY, config, reads) + buffer (NDJSON WAL)
internal/server        web UI (HTMX, embedded), API, OIDC, audit
internal/telemetry     Prometheus + slog
migrations/            SQL schema
deploy/                Dockerfile, docker-compose lab, Helm chart, systemd
test/redfishmock       fake BMC per vendor used by the tests
test/fakeccp           fake CyberArk CCP (mTLS) for tests and labs: go run ./test/fakeccp/cmd/fakeccp -dir /tmp/ccp -account BMC/a1:root:pw
```

## Development

```bash
make            # fmt + vet + test + build
make test       # go test -race ./...
```

Tests run a full collection cycle against five in-process fake BMCs (one per vendor
profile) without any database, and cover the quality validator and the buffer replay.
The secret cache and rotation logic are tested against an in-memory vault and against
`test/fakeccp`, a fake CyberArk CCP with mutual TLS (`internal/vault/ccp_integration_test.go`,
`internal/collector/secrets_test.go`). The SQL side of the manual sync (`migrations/0002`)
has no automated test yet: run `bmcgrab migrate` then `bmcgrab secrets sync` on a real database.
