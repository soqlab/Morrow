package main

// Morrow Shield: a quantum-safe TLS front door.
//
// Why there is no CurvePreferences anywhere in this file
//
// Go's crypto/tls negotiates the hybrid post-quantum key exchange X25519MLKEM768 by default when
// tls.Config.CurvePreferences is nil, and still offers the classical groups to clients that lack it:
//
//   - Go 1.24 release notes, section crypto/tls (https://go.dev/doc/go1.24): "The new
//     post-quantum X25519MLKEM768 key exchange mechanism is now supported and is enabled by default
//     when Config.CurvePreferences is nil. GODEBUG setting tlsmlkem=0 reverts the default." The same
//     notes: "Key exchange ordering is now handled entirely by the crypto/tls package."
//   - Go 1.26 release notes, section crypto/tls (https://go.dev/doc/go1.26): "The hybrid
//     SecP256r1MLKEM768 and SecP384r1MLKEM1024 post-quantum key exchanges are now enabled by
//     default. They can be disabled by setting Config.CurvePreferences or with the tlssecpmlkem=0
//     GODEBUG setting."
//   - crypto/tls docs, Config.CurvePreferences: "From Go 1.24, the default includes the
//     X25519MLKEM768 hybrid post-quantum key exchange. To disable it, set CurvePreferences
//     explicitly or use the GODEBUG=tlsmlkem=0 environment variable."
//     https://pkg.go.dev/crypto/tls#Config
//   - The default order in the standard library (src/crypto/tls/defaults.go, defaultCurvePreferences,
//     Go 1.26): X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519, P-256, P-384, P-521.
//     A client that offers X25519MLKEM768 gets it; one that offers only X25519 or P-256 gets that.
//   - ConnectionState.CurveID (Go 1.25+) names the group a connection negotiated; Shield counts it.
//     https://pkg.go.dev/crypto/tls#ConnectionState
//   - GODEBUG defaults follow the go line of go.mod (https://go.dev/doc/godebug), which is 1.26 here,
//     so the post-quantum defaults are on. Shield refuses to start if GODEBUG turns them off.
//
// Post-quantum key exchange exists only in TLS 1.3 (draft-ietf-tls-ecdhe-mlkem); a TLS 1.2 client
// still connects, classically. That is the "classical fallback for old clients".

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Safe defaults. Nothing here is tunable from the outside except the upstream timeout: long
// request bodies, streaming and WebSockets need no read or write deadline, so the limits are on
// headers and idle time instead.
const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 64 << 10
	maxUpstreamHeader = 1 << 20
	dialTimeout       = 10 * time.Second
	shutdownGrace     = 15 * time.Second
)

// PQGroups are the key-exchange groups Shield counts as post-quantum (hybrid ML-KEM).
var PQGroups = map[tls.CurveID]bool{
	tls.X25519MLKEM768:     true,
	tls.SecP256r1MLKEM768:  true,
	tls.SecP384r1MLKEM1024: true,
}

// GroupName is the IANA name of a key-exchange group ("none" for a non-ECDHE TLS 1.2 handshake).
func GroupName(id tls.CurveID) string {
	if id == 0 {
		return "none"
	}
	return id.String()
}

// pqDisabledByGODEBUG reports whether the GODEBUG environment variable turns the post-quantum
// default off (https://go.dev/doc/godebug: the last setting of a key wins).
func pqDisabledByGODEBUG(godebug string) bool {
	off := false
	for _, kv := range strings.Split(godebug, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(kv), "=")
		if k == "tlsmlkem" {
			off = v == "0"
		}
	}
	return off
}

// ── counters ────────────────────────────────────────────────────────────────

// Stats counts the key-exchange group of every completed handshake. No addresses, no hostnames,
// nothing per visitor: only how many connections used which group.
type Stats struct {
	mu       sync.Mutex
	groups   map[string]uint64
	versions map[string]uint64
	total    uint64
	pq       uint64
	started  time.Time
}

func NewStats() *Stats {
	return &Stats{groups: map[string]uint64{}, versions: map[string]uint64{}, started: time.Now().UTC()}
}

func (s *Stats) Record(st tls.ConnectionState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total++
	s.groups[GroupName(st.CurveID)]++
	s.versions[tls.VersionName(st.Version)]++
	if PQGroups[st.CurveID] {
		s.pq++
	}
}

type Snapshot struct {
	Since       string            `json:"since"`
	Connections uint64            `json:"connections"`
	PostQuantum uint64            `json:"post_quantum"`
	PQShare     float64           `json:"pq_share"`
	Groups      map[string]uint64 `json:"groups"`
	TLSVersions map[string]uint64 `json:"tls_versions"`
}

func (s *Stats) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Snapshot{Since: s.started.Format(time.RFC3339), Connections: s.total, PostQuantum: s.pq,
		Groups: map[string]uint64{}, TLSVersions: map[string]uint64{}}
	for k, v := range s.groups {
		out.Groups[k] = v
	}
	for k, v := range s.versions {
		out.TLSVersions[k] = v
	}
	if s.total > 0 {
		out.PQShare = float64(s.pq) / float64(s.total)
	}
	return out
}

func (sn Snapshot) groupList() string {
	keys := make([]string, 0, len(sn.Groups))
	for k := range sn.Groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return sn.Groups[keys[i]] > sn.Groups[keys[j]] || sn.Groups[keys[i]] == sn.Groups[keys[j]] && keys[i] < keys[j]
	})
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", k, sn.Groups[k])
	}
	return strings.Join(parts, " ")
}

// ── the shield ──────────────────────────────────────────────────────────────

type Shield struct {
	cfg     *Config
	log     *slog.Logger
	stats   *Stats
	acme    *autocert.Manager
	certs   *certFiles
	ready   atomic.Bool
	proxy   *httputil.ReverseProxy
	domains map[string]bool
}

// New builds a Shield from a validated Config. It reads the certificate files (when given) but
// opens no socket.
func New(cfg *Config, logger *slog.Logger) (*Shield, error) {
	if pqDisabledByGODEBUG(os.Getenv("GODEBUG")) {
		return nil, errors.New("GODEBUG has tlsmlkem=0, which turns off post-quantum key exchange: remove it, that is what Shield is for")
	}
	s := &Shield{cfg: cfg, log: logger, stats: NewStats(), domains: map[string]bool{}}
	for _, d := range cfg.Domains {
		s.domains[d] = true
	}
	transport, err := upstreamTransport(cfg)
	if err != nil {
		return nil, err
	}
	s.proxy = s.newProxy(transport)
	if cfg.ACME() {
		if err := os.MkdirAll(cfg.ACMEDir, 0o700); err != nil {
			return nil, fmt.Errorf("SHIELD_ACME_DIR %s: %v (mount a writable volume there)", cfg.ACMEDir, err)
		}
		s.acme = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(cfg.ACMEDir),
			HostPolicy: autocert.HostWhitelist(cfg.Domains...),
			Email:      cfg.ACMEEmail,
		}
		if cfg.ACMEURL != "" {
			s.acme.Client = &acme.Client{DirectoryURL: cfg.ACMEURL}
		}
	} else {
		if s.certs, err = loadCertFiles(cfg.CertFile, cfg.KeyFile); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// TLSConfig is the server side. CurvePreferences is left nil on purpose: see the top of this file.
func (s *Shield) TLSConfig() *tls.Config {
	c := &tls.Config{
		MinVersion: tls.VersionTLS12, // TLS 1.3 is preferred by Go; 1.2 is the classical fallback
		NextProtos: []string{"h2", "http/1.1"},
		// Called on the server side for every handshake, with CurveID already set
		// (crypto/tls handshake_server.go and handshake_server_tls13.go set curveID first).
		VerifyConnection: s.countHandshake,
	}
	if s.acme != nil {
		c.GetCertificate = s.acme.GetCertificate
		c.NextProtos = append(c.NextProtos, acme.ALPNProto) // tls-alpn-01 challenges on :443
	} else {
		c.GetCertificate = s.certs.get
	}
	return c
}

// countHandshake runs once per handshake (tls.Config.VerifyConnection), after the key exchange is
// agreed, so a connection is counted even if it never sends a request. It never refuses one.
func (s *Shield) countHandshake(st tls.ConnectionState) error {
	s.stats.Record(st)
	if s.cfg.LogConnections {
		s.log.Info("connection", "group", GroupName(st.CurveID), "post_quantum", PQGroups[st.CurveID],
			"tls", tls.VersionName(st.Version), "alpn", st.NegotiatedProtocol)
	}
	return nil
}

func (s *Shield) knownHost(host string) bool {
	if len(s.domains) == 0 {
		return true
	}
	return s.domains[normalizeHost(host)]
}

func normalizeHost(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// Handler is what the HTTPS listener serves: the reverse proxy, for the configured hosts only.
func (s *Shield) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.knownHost(r.Host) {
			http.Error(w, "This address is not served here.", http.StatusMisdirectedRequest)
			return
		}
		s.proxy.ServeHTTP(w, r)
	})
}

// HTTPHandler is what :80 serves: ACME http-01 challenges, and a redirect to HTTPS for the rest.
func (s *Shield) HTTPHandler() http.Handler {
	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := normalizeHost(r.Host)
		if host == "" || !s.knownHost(host) || validHostname(host) != nil && net.ParseIP(host) == nil {
			http.Error(w, "This address is not served here.", http.StatusMisdirectedRequest)
			return
		}
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		code := http.StatusPermanentRedirect // keeps the method and body
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			code = http.StatusMovedPermanently
		}
		w.Header().Set("Connection", "close")
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), code)
	})
	if s.acme != nil {
		return s.acme.HTTPHandler(redirect)
	}
	return redirect
}

// HealthHandler is the local-only port: /healthz for Docker, /stats for the owner.
func (s *Shield) HealthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !s.ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, "starting\n")
			return
		}
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.stats.Snapshot())
	})
	return mux
}

// forwardedFor is the RFC 7239 node for a client address: IPv6 in quotes and brackets.
func forwardedFor(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	if strings.Contains(host, ":") {
		return `"[` + host + `]"`
	}
	return host
}

func forwardedHost(h string) string {
	// RFC 7239 section 4: a value that is not a token must be a quoted string.
	for _, r := range h {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r)) {
			return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(h) + `"`
		}
	}
	return h
}

func (s *Shield) newProxy(transport http.RoundTripper) *httputil.ReverseProxy {
	up := s.cfg.Upstream
	return &httputil.ReverseProxy{
		// Rewrite (not Director): the visitor's own X-Forwarded-* and hop-by-hop headers are removed
		// before this runs, so a visitor cannot forge them. Shield is the first hop; it says who
		// connected, and drops any Forwarded header the visitor sent for the same reason.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(up)
			if s.cfg.UpstreamHost != "" {
				pr.Out.Host = s.cfg.UpstreamHost
			} else {
				pr.Out.Host = pr.In.Host
			}
			pr.SetXForwarded()
			proto := "http"
			if pr.In.TLS != nil {
				proto = "https"
			}
			pr.Out.Header.Set("Forwarded", "for="+forwardedFor(pr.In.RemoteAddr)+";host="+forwardedHost(pr.In.Host)+";proto="+proto)
		},
		Transport: transport,
		// Flush every write at once: server-sent events, long polls and other streams reach the
		// visitor as they are produced. WebSocket upgrades are handled by ReverseProxy itself.
		FlushInterval: -1,
		ErrorLog:      log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return // the visitor left
			}
			s.log.Warn("upstream unreachable", "error", err.Error())
			http.Error(w, "Shield could not reach the site behind it.", http.StatusBadGateway)
		},
	}
}

func upstreamTransport(cfg *Config) (*http.Transport, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.UpstreamCA != "" {
		pem, err := os.ReadFile(cfg.UpstreamCA)
		if err != nil {
			return nil, fmt.Errorf("SHIELD_UPSTREAM_CA: %v", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("SHIELD_UPSTREAM_CA %s has no PEM certificate", cfg.UpstreamCA)
		}
		tc.RootCAs = pool
	}
	tc.InsecureSkipVerify = cfg.Insecure
	d := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                  nil, // straight to the upstream; HTTP_PROXY variables are ignored
		DialContext:            d.DialContext,
		TLSClientConfig:        tc,
		TLSHandshakeTimeout:    dialTimeout,
		ResponseHeaderTimeout:  cfg.UpstreamTimeout,
		ExpectContinueTimeout:  time.Second,
		IdleConnTimeout:        90 * time.Second,
		MaxIdleConns:           256,
		MaxIdleConnsPerHost:    64,
		MaxResponseHeaderBytes: maxUpstreamHeader,
		ForceAttemptHTTP2:      true,
	}, nil
}

// ── certificate files, re-read when they change on disk ───────────────────

type certFiles struct {
	certPath, keyPath string
	mu                sync.Mutex
	cert              *tls.Certificate
	stamp             string
	checked           time.Time
}

func fileStamp(paths ...string) string {
	var b strings.Builder
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil {
			fmt.Fprintf(&b, "%d/%d;", fi.ModTime().UnixNano(), fi.Size())
		}
	}
	return b.String()
}

func loadCertFiles(certPath, keyPath string) (*certFiles, error) {
	c := &certFiles{certPath: certPath, keyPath: keyPath}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("SHIELD_CERT/SHIELD_KEY: %v", err)
	}
	c.cert, c.stamp, c.checked = &cert, fileStamp(certPath, keyPath), time.Now()
	return c, nil
}

// get serves the loaded pair, looking for a renewed one on disk at most every 30 seconds; a pair
// that fails to load keeps the previous one in service.
func (c *certFiles) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.checked) > 30*time.Second {
		c.checked = time.Now()
		if st := fileStamp(c.certPath, c.keyPath); st != c.stamp {
			if cert, err := tls.LoadX509KeyPair(c.certPath, c.keyPath); err == nil {
				c.cert, c.stamp = &cert, st
			}
		}
	}
	return c.cert, nil
}

// ── serving ─────────────────────────────────────────────────────────────────

func (s *Shield) servers() (httpsSrv, httpSrv, healthSrv *http.Server) {
	errLog := slog.NewLogLogger(s.log.Handler(), slog.LevelDebug) // handshake noise from scanners stays out of the log
	httpsSrv = &http.Server{
		Handler: s.Handler(), TLSConfig: s.TLSConfig(),
		ReadHeaderTimeout: readHeaderTimeout, IdleTimeout: idleTimeout, MaxHeaderBytes: maxHeaderBytes, ErrorLog: errLog,
	}
	httpSrv = &http.Server{
		Handler: s.HTTPHandler(), ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: maxHeaderBytes, ErrorLog: errLog,
	}
	healthSrv = &http.Server{
		Handler: s.HealthHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, ErrorLog: errLog,
	}
	return
}

// Serve runs on listeners the caller opened (httpLn and healthLn may be nil) until ctx ends.
func (s *Shield) Serve(ctx context.Context, httpsLn, httpLn, healthLn net.Listener) error {
	httpsSrv, httpSrv, healthSrv := s.servers()
	errs := make(chan error, 3)
	go func() { errs <- httpsSrv.ServeTLS(httpsLn, "", "") }()
	if httpLn != nil {
		go func() { errs <- httpSrv.Serve(httpLn) }()
	}
	if healthLn != nil {
		go func() { errs <- healthSrv.Serve(healthLn) }()
	}
	s.ready.Store(true)
	if s.cfg.Insecure {
		s.warnInsecure()
	}
	stop := make(chan struct{})
	defer close(stop)
	if s.cfg.StatsEvery > 0 {
		go s.logStats(stop)
	}
	var err error
	select {
	case <-ctx.Done():
	case err = <-errs:
	}
	s.ready.Store(false)
	shut, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	for _, srv := range []*http.Server{httpsSrv, httpSrv, healthSrv} {
		srv.Shutdown(shut)
	}
	s.logSnapshot()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Shield) logStats(stop <-chan struct{}) {
	t := time.NewTicker(s.cfg.StatsEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.logSnapshot()
			if s.cfg.Insecure {
				s.warnInsecure()
			}
		}
	}
}

func (s *Shield) logSnapshot() {
	sn := s.stats.Snapshot()
	s.log.Info("key exchange", "connections", sn.Connections, "post_quantum", sn.PostQuantum,
		"pq_share", fmt.Sprintf("%.1f%%", 100*sn.PQShare), "groups", sn.groupList(), "since", sn.Since)
}

func (s *Shield) warnInsecure() {
	s.log.Warn("UPSTREAM CERTIFICATE NOT VERIFIED: SHIELD_UPSTREAM_INSECURE is on, so anyone between Shield and " +
		s.cfg.Upstream.Host + " can read and change the traffic. Use SHIELD_UPSTREAM_CA with your upstream's CA instead.")
}

// Listen opens the configured sockets and serves until ctx ends.
func (s *Shield) Listen(ctx context.Context) error {
	httpsLn, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("SHIELD_LISTEN %s: %v", s.cfg.Listen, err)
	}
	var httpLn, healthLn net.Listener
	if s.cfg.HTTPListen != "" {
		if httpLn, err = net.Listen("tcp", s.cfg.HTTPListen); err != nil {
			httpsLn.Close()
			return fmt.Errorf("SHIELD_HTTP_LISTEN %s: %v", s.cfg.HTTPListen, err)
		}
	}
	if s.cfg.HealthListen != "" {
		if healthLn, err = net.Listen("tcp", s.cfg.HealthListen); err != nil {
			httpsLn.Close()
			if httpLn != nil {
				httpLn.Close()
			}
			return fmt.Errorf("SHIELD_HEALTH_LISTEN %s: %v", s.cfg.HealthListen, err)
		}
	}
	mode := "certificate files"
	if s.acme != nil {
		mode = "automatic (ACME)"
		if s.cfg.HTTPListen == "" {
			s.log.Warn("SHIELD_HTTP_LISTEN is off: certificates can still be issued over tls-alpn-01 on " + s.cfg.Listen + ", but visitors on http:// get no redirect")
		}
	}
	s.log.Info("shield up", "https", s.cfg.Listen, "http", s.cfg.HTTPListen, "health", s.cfg.HealthListen,
		"domains", strings.Join(s.cfg.Domains, ","), "upstream", s.cfg.Upstream.String(), "certificates", mode,
		"key_exchange", "X25519MLKEM768 preferred, classical for clients without it")
	return s.Serve(ctx, httpsLn, httpLn, healthLn)
}
