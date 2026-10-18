package main

import (
	"fmt"
	"os"
	"os/user"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/sealkrach/bmcgrab/internal/config"
)

// secretsCmd: `bmcgrab secrets sync|status`. Both talk to the central database
// only; the collectors do the actual vault work.
func secretsCmd() *cobra.Command {
	root := &cobra.Command{Use: "secrets", Short: "Manage the cached BMC secrets"}
	var region, serverID string
	syncCmd := &cobra.Command{
		Use:   "sync",
		Short: "Ask the collectors to refetch BMC secrets from the vault now (e.g. after a rotation)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.LoadLocal(flagConfig)
			if err != nil {
				return err
			}
			ctx, stop := signalContext()
			defer stop()
			store, err := openStore(ctx, cfg, 1)
			if err != nil {
				return err
			}
			defer store.Close()
			by := "cli"
			if u, err := user.Current(); err == nil {
				by = "cli:" + u.Username
			}
			id, err := store.RequestSecretSync(ctx, by, region, serverID)
			if err != nil {
				return err
			}
			_ = store.Audit(ctx, by, "secrets.sync", map[string]any{"request": id, "region": region, "server_id": serverID})
			fmt.Printf("sync #%d queued; collectors pick it up within ~10s. Follow with: bmcgrab secrets status\n", id)
			return nil
		},
	}
	syncCmd.Flags().StringVar(&region, "region", "", "only this region (default: all)")
	syncCmd.Flags().StringVar(&serverID, "server", "", "only this server id (default: all)")

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show the latest secret synchronisations per region",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.LoadLocal(flagConfig)
			if err != nil {
				return err
			}
			ctx, stop := signalContext()
			defer stop()
			store, err := openStore(ctx, cfg, 1)
			if err != nil {
				return err
			}
			defer store.Close()
			runs, err := store.SecretSyncRuns(ctx, 20)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "REQ\tREGION\tSTATUS\tSTARTED\tBY\tSCOPE\tREPORT")
			for _, r := range runs {
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", r.RequestID, r.Region, r.Status,
					r.StartedAt.Format("2006-01-02 15:04:05"), r.RequestedBy, r.Scope, string(r.Report))
			}
			return w.Flush()
		},
	}
	root.AddCommand(syncCmd, statusCmd)
	return root
}
