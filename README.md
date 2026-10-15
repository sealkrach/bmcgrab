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
```

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
internal/vault         CyberArk CCP client (+ env provider for labs)
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
```

## Development

```bash
make            # fmt + vet + test + build
make test       # go test -race ./...
```

Tests run a full collection cycle against five in-process fake BMCs (one per vendor
profile) without any database, and cover the quality validator and the buffer replay.

> **First build note.** `go.sum` was generated in a sandbox that could not reach
> `golang.org/x/*`, `gopkg.in` and `google.golang.org`, so their checksum lines are
> missing. Run `go mod tidy` once after cloning (it only adds those lines) before
> `make build`. CI runs it as its first step.
