// Command shield is Morrow Shield: a quantum-safe TLS front door for a site or an old app.
//
//	shield                       serve (configured by SHIELD_* variables or flags; see README.md)
//	shield check host[:port]     print which key exchange a server chooses
//	shield health                exit 0 when the local /healthz answers ok (for Docker HEALTHCHECK)
//	shield version
//
// Shield has no telemetry and never phones home. The only outbound connections it makes are to
// SHIELD_UPSTREAM and, for automatic certificates, to the ACME certificate authority.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// version is set at build time: -ldflags "-X main.version=0.1.0".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "check":
			return checkCmd(args[1:], stdout, stderr)
		case "health":
			return healthCmd(lookupOS, stderr)
		case "version", "-version", "--version":
			fmt.Fprintln(stdout, "morrow-shield", version)
			return 0
		case "help", "-h", "-help", "--help":
			usage(stdout)
			return 0
		}
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := LoadConfig(args, lookupOS, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "shield:", err)
		return 2
	}
	s, err := New(cfg, logger)
	if err != nil {
		fmt.Fprintln(stderr, "shield:", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := s.Listen(ctx); err != nil {
		fmt.Fprintln(stderr, "shield:", err)
		return 1
	}
	return 0
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Morrow Shield `+version+`: a quantum-safe TLS front door.

  shield                     serve; configure with SHIELD_* variables or flags (shield -h lists them)
  shield check host[:port]   print which key exchange a server chooses (0 post-quantum, 2 classical)
  shield health              exit 0 when the local /healthz answers ok
  shield version

Required: SHIELD_UPSTREAM, and SHIELD_DOMAINS (automatic certificates) or SHIELD_CERT + SHIELD_KEY.
`)
}

// healthCmd asks the local health port, so a distroless image (no shell, no curl) can still have a
// Docker HEALTHCHECK.
func healthCmd(lookup envLookup, stderr io.Writer) int {
	addr := "127.0.0.1:9180"
	if v, ok := lookup("SHIELD_HEALTH_LISTEN"); ok && off(v) != "" {
		addr = v
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintln(stderr, "shield health:", err)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		fmt.Fprintln(stderr, "shield health:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(stderr, "shield health:", resp.Status)
		return 1
	}
	return 0
}
