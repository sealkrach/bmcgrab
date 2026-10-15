// bmcgrab collects CPU/RAM usage, temperatures and power from server BMCs
// over Redfish, across vendors, into TimescaleDB.
//
//	bmcgrab collector --config /etc/bmcgrab/collector.yaml
//	bmcgrab server    --config /etc/bmcgrab/server.yaml
//	bmcgrab check     --config /etc/bmcgrab/collector.yaml [--sample 20]
//	bmcgrab migrate   --config /etc/bmcgrab/server.yaml
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/sealkrach/bmcgrab"
	"github.com/sealkrach/bmcgrab/internal/check"
	"github.com/sealkrach/bmcgrab/internal/collector"
	"github.com/sealkrach/bmcgrab/internal/config"
	"github.com/sealkrach/bmcgrab/internal/redfish/vendors"
	"github.com/sealkrach/bmcgrab/internal/server"
	"github.com/sealkrach/bmcgrab/internal/storage/buffer"
	"github.com/sealkrach/bmcgrab/internal/storage/timescale"
	"github.com/sealkrach/bmcgrab/internal/telemetry"
	"github.com/sealkrach/bmcgrab/internal/vault"
)

// version is set with -ldflags "-X main.version=..."
var version = "dev"

var (
	flagConfig   string
	flagLab      bool
	flagLogLevel string
)

func main() {
	root := &cobra.Command{Use: "bmcgrab", Short: "Multi-vendor Redfish telemetry collector", Version: version, SilenceUsage: true}
	root.PersistentFlags().StringVarP(&flagConfig, "config", "c", "/etc/bmcgrab/config.yaml", "local YAML config")
	root.PersistentFlags().BoolVar(&flagLab, "lab", false, "lab mode: allow env credentials and insecure TLS if central config asks for it")
	root.PersistentFlags().StringVar(&flagLogLevel, "log-level", "info", "debug|info|warn|error")

	var sample int
	chk := &cobra.Command{Use: "check", Short: "Pre-flight report: database, config, credential, inventory, BMCs",
		RunE: func(cmd *cobra.Command, _ []string) error { return runCheck(cmd, sample) }}
	chk.Flags().IntVar(&sample, "sample", 10, "number of BMCs to probe (0 = all)")

	root.AddCommand(
		&cobra.Command{Use: "collector", Short: "Run the regional collector", RunE: runCollector},
		&cobra.Command{Use: "server", Short: "Run the central web UI/API", RunE: runServer},
		&cobra.Command{Use: "migrate", Short: "Apply database migrations", RunE: runMigrate},
		chk,
	)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

func openStore(ctx context.Context, cfg *config.Local, maxConns int32) (*timescale.Store, error) {
	timescale.SetMigrations(bmcgrab.Migrations)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	st, err := timescale.Open(ctx, cfg.DatabaseDSN(), maxConns)
	if err != nil {
		return nil, err
	}
	if err := st.Ping(ctx); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}

func newVault(cfg *config.Local, log interface{ Warn(string, ...any) }) (vault.Provider, error) {
	if cfg.CyberArk.URL != "" {
		return vault.NewCyberArk(vault.CyberArkConfig{
			URL: cfg.CyberArk.URL, AppID: cfg.CyberArk.AppID, Safe: cfg.CyberArk.Safe, Object: cfg.CyberArk.Object,
			ClientCert: cfg.CyberArk.ClientCert, ClientKey: cfg.CyberArk.ClientKey, CAFile: cfg.CyberArk.CAFile, CacheTTL: cfg.CyberArk.CacheTTL,
		})
	}
	if !flagLab {
		return nil, errors.New("no cyberark section in config; env credentials require --lab")
	}
	u, p := cfg.LabCredentials.UsernameEnv, cfg.LabCredentials.PasswordEnv
	if u == "" {
		u = "BMCGRAB_BMC_USERNAME"
	}
	if p == "" {
		p = "BMCGRAB_BMC_PASSWORD"
	}
	log.Warn("lab mode: BMC credential read from environment", "user_env", u)
	return vault.NewEnv(u, p), nil
}

func runCollector(_ *cobra.Command, _ []string) error {
	log := telemetry.Logger(flagLogLevel)
	cfg, err := config.LoadLocal(flagConfig)
	if err != nil {
		return err
	}
	if err := cfg.Validate("collector"); err != nil {
		return err
	}
	ctx, stop := signalContext()
	defer stop()

	store, err := openStore(ctx, cfg, 4)
	if err != nil {
		log.Warn("database unreachable at start; cycles will be buffered until it returns", "err", err)
	}
	vp, err := newVault(cfg, log)
	if err != nil {
		return err
	}
	buf, err := buffer.New(cfg.Local.BufferDir, cfg.Local.MaxBufferMB<<20)
	if err != nil {
		return err
	}
	metrics := telemetry.NewMetrics(cfg.Region)
	col := collector.New(collector.Options{
		Local: cfg, Store: store, Vault: vp, Registry: vendors.All(), Buffer: buf, Metrics: metrics, Log: log, Version: version, Lab: flagLab,
	})
	srv := telemetry.Serve(cfg.Metrics.Listen, col.Healthy)
	defer srv.Close()
	log.Info("collector starting", "region", cfg.Region, "version", version, "vault", vp.Name(), "metrics", cfg.Metrics.Listen)
	err = col.Run(ctx)
	if errors.Is(err, context.Canceled) {
		log.Info("collector stopped")
		return nil
	}
	return err
}

func runServer(_ *cobra.Command, _ []string) error {
	log := telemetry.Logger(flagLogLevel)
	cfg, err := config.LoadLocal(flagConfig)
	if err != nil {
		return err
	}
	if err := cfg.Validate("server"); err != nil {
		return err
	}
	ctx, stop := signalContext()
	defer stop()
	store, err := openStore(ctx, cfg, 8)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer store.Close()
	_ = store.PruneHeartbeats(ctx, 30*24*time.Hour)

	// The server can run the pre-flight too when it has a credential source.
	var runner func(context.Context) *check.Report
	if vp, err := newVault(cfg, log); err == nil {
		runner = func(ctx context.Context) *check.Report {
			return check.Run(ctx, check.Options{Local: cfg, Store: store, Vault: vp, Registry: vendors.All(), Lab: flagLab, Sample: 10})
		}
	}
	h, err := server.New(ctx, server.Options{Local: cfg, Store: store, Log: log, Version: version, CheckRunner: runner})
	if err != nil {
		return err
	}
	metricsSrv := telemetry.Serve(cfg.Metrics.Listen, func() error { return store.Ping(context.Background()) })
	defer metricsSrv.Close()
	httpSrv := &http.Server{Addr: cfg.Server.Listen, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(sctx)
	}()
	log.Info("server starting", "listen", cfg.Server.Listen, "version", version)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func runMigrate(_ *cobra.Command, _ []string) error {
	cfg, err := config.LoadLocal(flagConfig)
	if err != nil {
		return err
	}
	ctx, stop := signalContext()
	defer stop()
	store, err := openStore(ctx, cfg, 2)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer store.Close()
	applied, err := store.Migrate(ctx)
	for _, a := range applied {
		fmt.Println("applied", a)
	}
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		fmt.Println("database is up to date")
	}
	return nil
}

func runCheck(_ *cobra.Command, sample int) error {
	log := telemetry.Logger("error")
	cfg, err := config.LoadLocal(flagConfig)
	if err != nil {
		return err
	}
	ctx, stop := signalContext()
	defer stop()
	store, storeErr := openStore(ctx, cfg, 2)
	if store != nil {
		defer store.Close()
	}
	vp, err := newVault(cfg, log)
	if err != nil {
		return err
	}
	rep := check.Run(ctx, check.Options{Local: cfg, Store: store, StoreErr: storeErr, Vault: vp, Registry: vendors.All(), Lab: flagLab, Sample: sample, Out: os.Stdout})
	if rep.Failed > 0 {
		os.Exit(2)
	}
	return nil
}
