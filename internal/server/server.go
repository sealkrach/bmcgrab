// Package server is the central web UI + read API, embedded in the binary.
// It only reads the database and edits the central config; it never talks to
// collectors or BMCs.
package server

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/sealkrach/bmcgrab/internal/check"
	"github.com/sealkrach/bmcgrab/internal/config"
	"github.com/sealkrach/bmcgrab/internal/storage/timescale"
)

//go:embed ui/templates/*.html ui/static/*
var uiFS embed.FS

// Options wire the server.
type Options struct {
	Local   *config.Local
	Store   *timescale.Store
	Log     *slog.Logger
	Version string
	// CheckRunner runs the pre-flight from the server's own vantage point.
	CheckRunner func(ctx context.Context) *check.Report
}

// Server holds handlers.
type Server struct {
	o    Options
	tpl  *template.Template
	auth *auth
}

// New builds the router.
func New(ctx context.Context, o Options) (http.Handler, error) {
	funcs := template.FuncMap{
		"ago":    ago,
		"dur":    func(d time.Duration) string { return d.Round(time.Second).String() },
		"json":   func(v any) template.JS { b, _ := json.Marshal(v); return template.JS(b) }, //nolint:gosec // our own data
		"title":  strings.Title,                                                              //nolint:staticcheck
		"fmtDur": func(d time.Duration) string { return d.String() },
		"list":   func(s ...string) []string { return s },
	}
	tpl, err := template.New("").Funcs(funcs).ParseFS(uiFS, "ui/templates/*.html")
	if err != nil {
		return nil, err
	}
	a, err := newAuth(ctx, o.Local.Server.OIDCIssuer, o.Local.Server.OIDCClient, o.Local.Server.OIDCSecret, o.Local.Server.RedirectURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: %w", err)
	}
	if !a.enabled {
		o.Log.Warn("server running WITHOUT authentication: set server.oidc_issuer in production")
	}
	s := &Server{o: o, tpl: tpl, auth: a}

	r := chi.NewRouter()
	r.Use(middleware.RealIP, middleware.Recoverer, middleware.Timeout(30*time.Second))
	r.Use(secureHeaders)
	static, _ := fs.Sub(uiFS, "ui/static")
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := o.Store.Ping(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok\n")) //nolint:errcheck
	})
	r.Get("/auth/callback", a.callback)
	r.Post("/auth/logout", a.logout)

	r.Group(func(r chi.Router) {
		r.Use(a.middleware)
		r.Get("/", s.dashboard)
		r.Get("/servers", s.servers)
		r.Get("/config", s.configPage)
		r.Post("/config", s.configSave)
		r.Post("/config/rollback/{version}", s.configRollback)
		r.Get("/check", s.checkPage)
		r.Post("/check/run", s.checkRun)
		r.Get("/audit", s.audit)
		// JSON API (same auth)
		r.Get("/api/regions", s.apiRegions)
		r.Get("/api/servers", s.apiServers)
		r.Get("/api/trend", s.apiTrend)
		r.Get("/api/config", s.apiConfig)
		// HTMX partials
		r.Get("/partials/overview", s.partialOverview)
	})
	return r, nil
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:")
		next.ServeHTTP(w, r)
	})
}

type page struct {
	Title   string
	Active  string
	User    string
	Version string
	Auth    bool
	Flash   string
	Error   string
	Data    any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, p page) {
	p.User, p.Version, p.Auth = user(r), s.o.Version, s.auth.enabled
	var buf bytes.Buffer
	if err := s.tpl.ExecuteTemplate(&buf, name, p); err != nil {
		s.o.Log.Error("render", "template", name, "err", err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// ---------------------------------------------------------------- pages

type overview struct {
	Totals      timescale.Totals
	Regions     []timescale.RegionSummary
	Failed      []timescale.ServerRow
	Unsupported map[string]map[string]int
	Interval    time.Duration
}

func (s *Server) loadOverview(ctx context.Context) (overview, error) {
	cfg, err := s.o.Store.LoadConfig(ctx)
	interval := 5 * time.Minute
	if err == nil {
		interval = cfg.Collect.Interval
	}
	var o overview
	o.Interval = interval
	if o.Totals, err = s.o.Store.Totals(ctx); err != nil {
		return o, err
	}
	if o.Regions, err = s.o.Store.Regions(ctx, 2*interval+time.Minute); err != nil {
		return o, err
	}
	if o.Failed, err = s.o.Store.Servers(ctx, "", "failed", "", 10); err != nil {
		return o, err
	}
	o.Unsupported, _ = s.o.Store.UnsupportedByVendor(ctx)
	return o, nil
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	o, err := s.loadOverview(r.Context())
	p := page{Title: "Dashboard", Active: "dashboard", Data: o}
	if err != nil {
		p.Error = err.Error()
	}
	s.render(w, r, "dashboard.html", p)
}

func (s *Server) partialOverview(w http.ResponseWriter, r *http.Request) {
	o, err := s.loadOverview(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "overview.html", page{Data: o})
}

func (s *Server) servers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rows, err := s.o.Store.Servers(r.Context(), q.Get("region"), q.Get("status"), q.Get("q"), 500)
	regions, _ := s.o.Store.Regions(r.Context(), time.Hour)
	p := page{Title: "Servers", Active: "servers", Data: map[string]any{
		"Rows": rows, "Regions": regions, "Region": q.Get("region"), "Status": q.Get("status"), "Q": q.Get("q"),
	}}
	if err != nil {
		p.Error = err.Error()
	}
	s.render(w, r, "servers.html", p)
}

func (s *Server) configPage(w http.ResponseWriter, r *http.Request) {
	s.renderConfig(w, r, "", "")
}

func (s *Server) renderConfig(w http.ResponseWriter, r *http.Request, flash, errMsg string) {
	cfg, err := s.o.Store.LoadConfig(r.Context())
	if err != nil {
		cfg = config.Default()
		errMsg = "no central config yet: " + err.Error()
	}
	hist, _ := s.o.Store.ConfigHistory(r.Context(), 20)
	s.render(w, r, "config.html", page{Title: "Configuration", Active: "config", Flash: flash, Error: errMsg,
		Data: map[string]any{"Cfg": cfg, "History": hist, "Enabled": strings.Join(cfg.Metrics.Enabled, ",")}})
}

func (s *Server) configSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	cfg, err := s.o.Store.LoadConfig(r.Context())
	if err != nil {
		cfg = config.Default()
	}
	f := r.PostForm
	parseErr := func(field string, err error) string {
		return fmt.Sprintf("field %s: %v", field, err)
	}
	var problems []string
	dur := func(k string, dst *time.Duration) {
		if v := f.Get(k); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				problems = append(problems, parseErr(k, err))
				return
			}
			*dst = d
		}
	}
	num := func(k string, dst *float64) {
		if v := f.Get(k); v != "" {
			x, err := strconv.ParseFloat(v, 64)
			if err != nil {
				problems = append(problems, parseErr(k, err))
				return
			}
			*dst = x
		}
	}
	integer := func(k string, dst *int) {
		if v := f.Get(k); v != "" {
			x, err := strconv.Atoi(v)
			if err != nil {
				problems = append(problems, parseErr(k, err))
				return
			}
			*dst = x
		}
	}
	dur("collect.interval", &cfg.Collect.Interval)
	integer("collect.workers", &cfg.Collect.Workers)
	dur("collect.timeout", &cfg.Collect.Timeout)
	integer("collect.retries", &cfg.Collect.Retries)
	var bf int
	bf = int(cfg.Breaker.Failures)
	integer("breaker.failures", &bf)
	cfg.Breaker.Failures = uint32(bf)
	dur("breaker.cooldown", &cfg.Breaker.Cooldown)
	num("quality.temp_min_c", &cfg.Quality.TempMinC)
	num("quality.temp_max_c", &cfg.Quality.TempMaxC)
	num("quality.power_min_w", &cfg.Quality.PowerMinW)
	num("quality.power_max_w", &cfg.Quality.PowerMaxW)
	dur("quality.max_clock_skew", &cfg.Quality.MaxClockSkew)
	cfg.Metrics.Enabled = f["metrics.enabled"]
	cfg.Inventory.Type = f.Get("inventory.type")
	dur("inventory.refresh", &cfg.Inventory.Refresh)
	cfg.Inventory.SQL.DSN = f.Get("inventory.sql.dsn")
	cfg.Inventory.SQL.PasswordEnv = f.Get("inventory.sql.password_env")
	cfg.Inventory.SQL.Query = f.Get("inventory.sql.query")
	cfg.Inventory.REST.URL = f.Get("inventory.rest.url")
	cfg.Inventory.REST.JSONPath = f.Get("inventory.rest.json_path")
	cfg.Inventory.REST.TokenEnv = f.Get("inventory.rest.token_env")
	cfg.Inventory.CSV.Path = f.Get("inventory.csv.path")
	cfg.TLS.InsecureSkipVerify = f.Get("tls.insecure_skip_verify") == "on"

	if len(problems) > 0 {
		s.renderConfig(w, r, "", strings.Join(problems, "; "))
		return
	}
	if err := cfg.Validate(); err != nil {
		s.renderConfig(w, r, "", err.Error())
		return
	}
	v, err := s.o.Store.SaveConfig(r.Context(), cfg, user(r))
	if err != nil {
		s.renderConfig(w, r, "", err.Error())
		return
	}
	_ = s.o.Store.Audit(r.Context(), user(r), "config.save", map[string]any{"version": v})
	s.renderConfig(w, r, fmt.Sprintf("Saved as version %d. Collectors pick it up on their next cycle.", v), "")
}

func (s *Server) configRollback(w http.ResponseWriter, r *http.Request) {
	v, _ := strconv.Atoi(chi.URLParam(r, "version"))
	hist, err := s.o.Store.ConfigHistory(r.Context(), 200)
	if err != nil {
		s.renderConfig(w, r, "", err.Error())
		return
	}
	for _, h := range hist {
		if h.Version == v {
			c := h
			nv, err := s.o.Store.SaveConfig(r.Context(), &c, user(r)+" (rollback to v"+strconv.Itoa(v)+")")
			if err != nil {
				s.renderConfig(w, r, "", err.Error())
				return
			}
			_ = s.o.Store.Audit(r.Context(), user(r), "config.rollback", map[string]any{"from": v, "version": nv})
			s.renderConfig(w, r, fmt.Sprintf("Version %d re-applied as version %d.", v, nv), "")
			return
		}
	}
	s.renderConfig(w, r, "", "version not found")
}

func (s *Server) checkPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "check.html", page{Title: "Check", Active: "check"})
}

func (s *Server) checkRun(w http.ResponseWriter, r *http.Request) {
	if s.o.CheckRunner == nil {
		http.Error(w, "check not available in this mode", http.StatusNotImplemented)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	rep := s.o.CheckRunner(ctx)
	_ = s.o.Store.Audit(r.Context(), user(r), "check.run", map[string]any{"failed": rep.Failed})
	s.render(w, r, "check_result.html", page{Data: rep})
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	rows, err := s.o.Store.Pool().Query(r.Context(), `SELECT time, actor, action, details FROM audit_log ORDER BY id DESC LIMIT 200`)
	type entry struct {
		Time    time.Time
		Actor   string
		Action  string
		Details string
	}
	var out []entry
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var e entry
			var d []byte
			if rows.Scan(&e.Time, &e.Actor, &e.Action, &d) == nil {
				e.Details = string(d)
				out = append(out, e)
			}
		}
	}
	p := page{Title: "Audit", Active: "audit", Data: out}
	if err != nil {
		p.Error = err.Error()
	}
	s.render(w, r, "audit.html", p)
}

// ------------------------------------------------------------------ API

func writeJSON(w http.ResponseWriter, v any, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) apiRegions(w http.ResponseWriter, r *http.Request) {
	v, err := s.o.Store.Regions(r.Context(), 15*time.Minute)
	writeJSON(w, v, err)
}

func (s *Server) apiServers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	v, err := s.o.Store.Servers(r.Context(), q.Get("region"), q.Get("status"), q.Get("q"), 5000)
	writeJSON(w, v, err)
}

func (s *Server) apiTrend(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name := q.Get("name")
	if name == "" {
		name = "power_w"
	}
	window, bucket := 24*time.Hour, 15*time.Minute
	if d, err := time.ParseDuration(q.Get("window")); err == nil {
		window = d
		bucket = window / 96
	}
	v, err := s.o.Store.Trend(r.Context(), q.Get("region"), name, window, bucket)
	writeJSON(w, v, err)
}

func (s *Server) apiConfig(w http.ResponseWriter, r *http.Request) {
	v, err := s.o.Store.LoadConfig(r.Context())
	writeJSON(w, v, err)
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return t.Format("2006-01-02 15:04")
}
