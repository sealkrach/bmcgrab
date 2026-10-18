// Command fakeccp runs the fake CCP for manual lab tests:
//
//	go run ./test/fakeccp/cmd/fakeccp -dir /tmp/fakeccp -account BMC/acct1:root:pw1
//
// then point cyberark.url / client_cert / client_key / ca_file at the files it
// prints. Not for production use.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sealkrach/bmcgrab/test/fakeccp"
)

type accounts []string

func (a *accounts) String() string     { return strings.Join(*a, ",") }
func (a *accounts) Set(v string) error { *a = append(*a, v); return nil }

func main() {
	dir := flag.String("dir", "", "directory for the generated certificates (required)")
	appID := flag.String("app-id", "BMCGrab", "AppID accepted by the server")
	var accts accounts
	flag.Var(&accts, "account", "safe/object:user:password (repeatable)")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "-dir is required")
		os.Exit(2)
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	s, err := fakeccp.New(*dir, *appID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer s.Close()
	for _, a := range accts {
		ref, rest, ok := strings.Cut(a, ":")
		user, pass, ok2 := strings.Cut(rest, ":")
		safe, obj, ok3 := strings.Cut(ref, "/")
		if !ok || !ok2 || !ok3 {
			fmt.Fprintf(os.Stderr, "bad -account %q, want safe/object:user:password\n", a)
			os.Exit(2)
		}
		s.Set(safe, obj, user, pass)
	}
	fmt.Printf("url:         %s\napp_id:      %s\nca_file:     %s\nclient_cert: %s\nclient_key:  %s\n",
		s.URL, *appID, s.CAFile, s.ClientCertFile, s.ClientKeyFile)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}
