// Package check runs the pre-flight report: database, config, CyberArk,
// inventory and a sample of BMCs. Output is plain text, green/red, meant to
// be read by an operator before trusting a new deployment.
package check

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sealkrach/bmcgrab/internal/config"
	"github.com/sealkrach/bmcgrab/internal/inventory"
	"github.com/sealkrach/bmcgrab/internal/model"
	"github.com/sealkrach/bmcgrab/internal/redfish"
	"github.com/sealkrach/bmcgrab/internal/storage/timescale"
	"github.com/sealkrach/bmcgrab/internal/vault"
)

// Options for a check run.
type Options struct {
	Local    *config.Local
	Store    *timescale.Store // nil if DB unreachable
	StoreErr error
	Vault    vault.Provider
	Registry *redfish.Registry
	Lab      bool
	Sample   int // how many BMCs to probe (0 = all)
	Out      io.Writer
}

// Report is the machine-readable outcome (also used by the web UI).
type Report struct {
	Items  []Item
	Failed int
}

// Item is one line of the report.
type Item struct {
	Name   string
	OK     bool
	Detail string
}

func (r *Report) add(name string, ok bool, detail string) {
	r.Items = append(r.Items, Item{Name: name, OK: ok, Detail: detail})
	if !ok {
		r.Failed++
	}
}

// Run executes every check and prints the report.
func Run(ctx context.Context, o Options) *Report {
	rep := &Report{}
	defer func() { print(o.Out, rep) }()

	// 1. database
	var cfg *config.Central
	if o.Store == nil {
		rep.add("database", false, errStr(o.StoreErr))
		cfg = config.Default()
	} else if err := o.Store.Ping(ctx); err != nil {
		rep.add("database", false, err.Error())
		cfg = config.Default()
	} else {
		rep.add("database", true, "reachable")
		c, err := o.Store.LoadConfig(ctx)
		if err != nil {
			rep.add("central config", false, err.Error()+" (run `bmcgrab migrate`?)")
			cfg = config.Default()
		} else {
			rep.add("central config", true, fmt.Sprintf("version %d by %s, interval %s, %d workers", c.Version, c.Author, c.Collect.Interval, c.Collect.Workers))
			cfg = c
		}
	}

	// 2. credential
	cred, err := o.Vault.Get(ctx)
	if err != nil {
		rep.add("credential ("+o.Vault.Name()+")", false, err.Error())
	} else {
		rep.add("credential ("+o.Vault.Name()+")", true, "user "+cred.Username)
	}

	// 3. inventory
	var servers []model.Server
	if p, err := inventory.New(cfg); err != nil {
		rep.add("inventory", false, err.Error())
	} else if servers, err = p.List(ctx, o.Local.Region); err != nil {
		rep.add("inventory ("+p.Name()+")", false, err.Error())
	} else {
		rep.add("inventory ("+p.Name()+")", len(servers) > 0, fmt.Sprintf("%d servers in region %q", len(servers), o.Local.Region))
	}

	// 4. BMCs
	if cred.Password == "" || len(servers) == 0 {
		return rep
	}
	insecure := cfg.TLS.InsecureSkipVerify && o.Lab
	client, err := redfish.NewClient(redfish.ClientOptions{CAFile: o.Local.TLS.CAFile, InsecureSkipVerify: insecure, Timeout: cfg.Collect.Timeout})
	if err != nil {
		rep.add("redfish client", false, err.Error())
		return rep
	}
	if cfg.TLS.InsecureSkipVerify && !o.Lab {
		rep.add("tls", false, "central config asks insecure_skip_verify but --lab not set: verification stays ON")
	}
	n := len(servers)
	if o.Sample > 0 && o.Sample < n {
		n = o.Sample
	}
	families := []model.Family{model.FamilyCPU, model.FamilyMemory, model.FamilyThermal, model.FamilyPower}
	for _, sv := range servers[:n] {
		addr := sv.BMCAddr
		if !strings.HasPrefix(addr, "http") {
			addr = "https://" + addr
		}
		cctx, cancel := context.WithTimeout(ctx, cfg.Collect.Timeout)
		s, err := client.Open(cctx, redfish.Target{BaseURL: addr, Username: cred.Username, Password: cred.Password})
		if err != nil {
			cancel()
			rep.add("bmc "+sv.Hostname, false, err.Error())
			continue
		}
		manu := sv.Vendor
		if manu == "" {
			manu = s.Manufacturer()
		}
		a := o.Registry.Resolve(manu)
		r := redfish.Collect(cctx, s, a, families)
		cancel()
		var parts []string
		allBad := true
		for _, f := range r.Families {
			mark := "✗"
			switch f.State {
			case model.StateCollected:
				mark, allBad = "✓", false
			case model.StateUnsupported:
				mark = "–"
			}
			parts = append(parts, fmt.Sprintf("%s %s", mark, f.Family))
		}
		rep.add("bmc "+sv.Hostname, !allBad, fmt.Sprintf("%s (%s) %s", a.Vendor(), s.Model(), strings.Join(parts, "  ")))
	}
	return rep
}

func errStr(err error) string {
	if err == nil {
		return "not configured"
	}
	return err.Error()
}

func print(w io.Writer, r *Report) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, "bmcgrab check — %s\n\n", time.Now().Format(time.RFC1123))
	for _, it := range r.Items {
		mark := "\033[32mOK \033[0m"
		if !it.OK {
			mark = "\033[31mFAIL\033[0m"
		}
		fmt.Fprintf(w, "  %s  %-28s %s\n", mark, it.Name, it.Detail)
	}
	fmt.Fprintln(w)
	if r.Failed == 0 {
		fmt.Fprintln(w, "All checks passed. Legend for BMC lines: ✓ collected  – unsupported by firmware  ✗ error")
	} else {
		fmt.Fprintf(w, "%d check(s) failed.\n", r.Failed)
	}
}
