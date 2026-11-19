package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Exit codes of `shield check`.
const (
	checkPQ        = 0 // the server chose a post-quantum key exchange
	checkError     = 1 // no handshake (unreachable, bad certificate, bad arguments)
	checkClassical = 2 // the server chose a classical key exchange
)

// CheckResult is what one handshake showed.
type CheckResult struct {
	Address     string
	ServerName  string
	Group       tls.CurveID
	Version     uint16
	CipherSuite uint16
	Subject     string
	Issuer      string
	NotAfter    time.Time
	Verified    bool
}

func (r CheckResult) PostQuantum() bool { return PQGroups[r.Group] }

// Check connects to addr the way a current browser does: it offers X25519MLKEM768 and the
// classical groups (Go's defaults, CurvePreferences nil), and reports what the server chose.
// With classicalOnly it offers no post-quantum group, to see what an old client gets.
func Check(addr, serverName string, insecure, classicalOnly bool, timeout time.Duration) (CheckResult, error) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), "443")
	}
	host, _, _ := net.SplitHostPort(addr)
	if serverName == "" && net.ParseIP(host) == nil {
		serverName = host
	}
	cfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS12}
	if classicalOnly {
		cfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, cfg)
	if err != nil {
		return CheckResult{Address: addr, ServerName: serverName}, err
	}
	defer conn.Close()
	st := conn.ConnectionState()
	r := CheckResult{Address: addr, ServerName: serverName, Group: st.CurveID, Version: st.Version,
		CipherSuite: st.CipherSuite, Verified: !insecure}
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		r.Subject, r.Issuer, r.NotAfter = leaf.Subject.CommonName, leaf.Issuer.CommonName, leaf.NotAfter
		if r.Subject == "" && len(leaf.DNSNames) > 0 {
			r.Subject = leaf.DNSNames[0]
		}
	}
	return r, nil
}

func checkCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("shield check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	insecure := fs.Bool("insecure", false, "do not verify the certificate (for a local test with a self-signed one)")
	sni := fs.String("servername", "", "TLS server name to send (default: the host)")
	classical := fs.Bool("classical", false, "offer only classical groups, as an old client would")
	timeout := fs.Duration("timeout", 10*time.Second, "connect and handshake timeout")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: shield check [-insecure] [-servername name] [-classical] host[:port]")
		fmt.Fprintln(stderr, "Connects like a current browser and prints which key exchange the server chooses.")
		fmt.Fprintln(stderr, "Exit status: 0 post-quantum, 2 classical, 1 no handshake.")
		fs.PrintDefaults()
	}
	// Flags may come before or after the address.
	var target string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return checkError
		}
		if fs.NArg() == 0 {
			break
		}
		if target != "" {
			fs.Usage()
			return checkError
		}
		target, rest = fs.Arg(0), fs.Args()[1:]
	}
	if target == "" {
		fs.Usage()
		return checkError
	}
	r, err := Check(target, *sni, *insecure, *classical, *timeout)
	fmt.Fprintf(stdout, "shield check %s\n", r.Address)
	if err != nil {
		fmt.Fprintf(stdout, "  no handshake   %v\n", err)
		return checkError
	}
	kind := "classical"
	if r.PostQuantum() {
		kind = "hybrid post-quantum"
	}
	offered := "X25519MLKEM768 and classical groups, as a current browser does"
	if *classical {
		offered = "classical groups only, as an old client does"
	}
	fmt.Fprintf(stdout, "  offered        %s\n", offered)
	fmt.Fprintf(stdout, "  key exchange   %s (%s)\n", GroupName(r.Group), kind)
	fmt.Fprintf(stdout, "  TLS version    %s\n", tls.VersionName(r.Version))
	fmt.Fprintf(stdout, "  cipher suite   %s\n", tls.CipherSuiteName(r.CipherSuite))
	if r.Subject != "" {
		verified := "verified"
		if !r.Verified {
			verified = "NOT verified (-insecure)"
		}
		fmt.Fprintf(stdout, "  certificate    %s, issued by %s, expires %s, %s\n", r.Subject, r.Issuer, r.NotAfter.UTC().Format("2006-01-02"), verified)
	}
	if r.PostQuantum() {
		fmt.Fprintln(stdout, "  verdict        quantum-safe: the server chose a post-quantum key exchange")
		return checkPQ
	}
	if *classical {
		fmt.Fprintln(stdout, "  verdict        an old client still connects, classically")
	} else {
		fmt.Fprintln(stdout, "  verdict        not quantum-safe: the server chose a classical key exchange")
	}
	return checkClassical
}
