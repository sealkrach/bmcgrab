// Package telemetry exposes Prometheus metrics and structured logging for
// both modes.
package telemetry

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Logger builds the process-wide JSON logger.
func Logger(level string) *slog.Logger {
	var lv slog.Level
	_ = lv.UnmarshalText([]byte(level))
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv}))
}

// Metrics are the collector's own counters and gauges.
type Metrics struct {
	CycleDuration   prometheus.Histogram
	CycleServers    *prometheus.GaugeVec // status label
	ServerDuration  prometheus.Histogram
	BreakerOpen     prometheus.Gauge
	Rejected        *prometheus.CounterVec // metric name
	Unsupported     *prometheus.GaugeVec   // vendor, family
	BufferBytes     prometheus.Gauge
	BufferSegments  prometheus.Gauge
	DBWriteErrors   prometheus.Counter
	InventorySize   prometheus.Gauge
	InventoryErrors prometheus.Counter
	VaultErrors     prometheus.Counter
	VaultFetch      *prometheus.CounterVec // result: ok|error
	VaultStale      prometheus.Counter
	VaultEntries    prometheus.Gauge
	VaultRotations  prometheus.Counter
	VaultAuthFail   prometheus.Counter
	VaultSyncDur    prometheus.Histogram
	ConfigVersion   prometheus.Gauge
	LastCycle       prometheus.Gauge
}

// NewMetrics registers everything under the bmcgrab_ prefix.
func NewMetrics(region string) *Metrics {
	l := prometheus.Labels{"region": region}
	f := promauto(l)
	m := &Metrics{
		CycleDuration:   f.hist("cycle_duration_seconds", "Duration of a full collection cycle.", []float64{5, 15, 30, 60, 120, 300, 600}),
		CycleServers:    f.gaugeVec("cycle_servers", "Servers per status in the last cycle.", "status"),
		ServerDuration:  f.hist("server_duration_seconds", "Per-server collection time.", []float64{.5, 1, 2, 5, 10, 20, 30}),
		BreakerOpen:     f.gauge("breaker_open", "BMCs currently paused by the circuit breaker."),
		Rejected:        f.counterVec("samples_rejected_total", "Samples dropped by quality validation.", "name"),
		Unsupported:     f.gaugeVec("family_unsupported", "Servers reporting a family as unsupported.", "vendor", "family"),
		BufferBytes:     f.gauge("buffer_bytes", "Bytes waiting in the local buffer."),
		BufferSegments:  f.gauge("buffer_segments", "Segments waiting in the local buffer."),
		DBWriteErrors:   f.counter("db_write_errors_total", "Failed writes to the central database."),
		InventorySize:   f.gauge("inventory_servers", "Servers returned by the inventory."),
		InventoryErrors: f.counter("inventory_errors_total", "Failed inventory refreshes."),
		VaultErrors:     f.counter("vault_errors_total", "Failed credential retrievals."),
		VaultFetch:      f.counterVec("vault_fetch_total", "Requests to the vault, by result.", "result"),
		VaultStale:      f.counter("vault_stale_served_total", "Secrets served stale because the vault failed."),
		VaultEntries:    f.gauge("vault_cache_entries", "Accounts held in the secret cache."),
		VaultRotations:  f.counter("vault_rotations_detected_total", "Accounts whose password changed between two fetches."),
		VaultAuthFail:   f.counter("vault_auth_failures_total", "BMC logins rejected with a credential from the vault."),
		VaultSyncDur:    f.hist("vault_sync_duration_seconds", "Duration of one secret synchronisation.", []float64{.5, 1, 5, 15, 30, 60, 300}),
		ConfigVersion:   f.gauge("config_version", "Central config version in use."),
		LastCycle:       f.gauge("last_cycle_timestamp_seconds", "Unix time of the last completed cycle."),
	}
	return m
}

type factory struct{ labels prometheus.Labels }

func promauto(l prometheus.Labels) factory { return factory{labels: l} }

func (f factory) gauge(name, help string) prometheus.Gauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "bmcgrab", Name: name, Help: help, ConstLabels: f.labels})
	prometheus.MustRegister(g)
	return g
}
func (f factory) counter(name, help string) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{Namespace: "bmcgrab", Name: name, Help: help, ConstLabels: f.labels})
	prometheus.MustRegister(c)
	return c
}
func (f factory) hist(name, help string, buckets []float64) prometheus.Histogram {
	h := prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: "bmcgrab", Name: name, Help: help, Buckets: buckets, ConstLabels: f.labels})
	prometheus.MustRegister(h)
	return h
}
func (f factory) gaugeVec(name, help string, labels ...string) *prometheus.GaugeVec {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "bmcgrab", Name: name, Help: help, ConstLabels: f.labels}, labels)
	prometheus.MustRegister(g)
	return g
}
func (f factory) counterVec(name, help string, labels ...string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "bmcgrab", Name: name, Help: help, ConstLabels: f.labels}, labels)
	prometheus.MustRegister(c)
	return c
}

// Serve starts the /metrics + /healthz endpoint. healthy is polled on each
// /healthz request.
func Serve(addr string, healthy func() error) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if err := healthy(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.ListenAndServe() }()
	return srv
}
