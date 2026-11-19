package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testHost = "shop.example.test"

// ── helpers ─────────────────────────────────────────────────────────────────

type testCert struct {
	certPath, keyPath string
	pool              *x509.CertPool
}

func makeCert(t *testing.T, names ...string) testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	kder, _ := x509.MarshalECPrivateKey(key)
	c := testCert{certPath: filepath.Join(dir, "cert.pem"), keyPath: filepath.Join(dir, "key.pem"), pool: x509.NewCertPool()}
	os.WriteFile(c.certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(c.keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
	leaf, _ := x509.ParseCertificate(der)
	c.pool.AddCert(leaf)
	return c
}

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *logBuf) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

type running struct {
	shield              *Shield
	https, http, health string
	cert                testCert
	logs                *logBuf
}

func env(m map[string]string) envLookup {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

// start runs a Shield in front of upstream on loopback ports, with a test certificate.
func start(t *testing.T, upstream string, extra map[string]string) *running {
	t.Helper()
	cert := makeCert(t, testHost)
	vars := map[string]string{
		"SHIELD_DOMAINS": testHost, "SHIELD_UPSTREAM": upstream,
		"SHIELD_CERT": cert.certPath, "SHIELD_KEY": cert.keyPath, "SHIELD_STATS_EVERY": "0",
	}
	for k, v := range extra {
		vars[k] = v
	}
	cfg, err := LoadConfig(nil, env(vars), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	logs := &logBuf{}
	s, err := New(cfg, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	listen := func() net.Listener {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return ln
	}
	a, b, c := listen(), listen(), listen()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Serve(ctx, a, b, c); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return &running{shield: s, https: a.Addr().String(), http: b.Addr().String(), health: c.Addr().String(), cert: cert, logs: logs}
}

// client talks to the Shield at addr as if DNS for testHost pointed there.
func (r *running) client(curves []tls.CurveID, maxVersion uint16) *http.Client {
	tc := &tls.Config{RootCAs: r.cert.pool, ServerName: testHost, CurvePreferences: curves, MaxVersion: maxVersion}
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: tc, ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, r.https)
		},
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func echoUpstream(t *testing.T) (*httptest.Server, chan *http.Request) {
	t.Helper()
	seen := make(chan *http.Request, 8)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Clone(context.Background())
		w.Header().Set("X-Upstream", "yes")
		io.WriteString(w, "hello from upstream "+r.URL.RequestURI())
	}))
	t.Cleanup(up.Close)
	return up, seen
}

// ── key exchange ────────────────────────────────────────────────────────────

func TestPostQuantumClientGetsX25519MLKEM768(t *testing.T) {
	up, _ := echoUpstream(t)
	r := start(t, up.URL, nil)
	// A client with Go's default groups offers X25519MLKEM768, as Chrome, Firefox and Safari do.
	conn, err := tls.Dial("tcp", r.https, &tls.Config{RootCAs: r.cert.pool, ServerName: testHost})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	st := conn.ConnectionState()
	if st.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("negotiated %v, want X25519MLKEM768", st.CurveID)
	}
	if st.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated %s, want TLS 1.3", tls.VersionName(st.Version))
	}
	if cfg := r.shield.TLSConfig(); cfg.CurvePreferences != nil {
		t.Fatalf("CurvePreferences must stay nil so Go's post-quantum default applies, got %v", cfg.CurvePreferences)
	}
	resp, err := r.client(nil, 0).Get("https://" + testHost + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.TLS.CurveID != tls.X25519MLKEM768 || resp.StatusCode != 200 {
		t.Fatalf("request over %v answered %d", resp.TLS.CurveID, resp.StatusCode)
	}
}

func TestClassicalClientsStillConnect(t *testing.T) {
	up, _ := echoUpstream(t)
	r := start(t, up.URL, nil)
	cases := []struct {
		name   string
		curves []tls.CurveID
		max    uint16
		want   tls.CurveID
	}{
		{"TLS 1.3 without ML-KEM", []tls.CurveID{tls.X25519}, 0, tls.X25519},
		{"P-256 only", []tls.CurveID{tls.CurveP256}, 0, tls.CurveP256},
		{"TLS 1.2 client", nil, tls.VersionTLS12, tls.X25519},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := r.client(c.curves, c.max).Get("https://" + testHost + "/old")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.TLS.CurveID != c.want || !strings.Contains(string(body), "hello from upstream /old") {
				t.Fatalf("got %v %q", resp.TLS.CurveID, body)
			}
			if PQGroups[resp.TLS.CurveID] {
				t.Fatal("a classical client cannot have a post-quantum group")
			}
		})
	}
}

func TestCountersShowThePostQuantumShare(t *testing.T) {
	up, _ := echoUpstream(t)
	r := start(t, up.URL, map[string]string{"SHIELD_LOG_CONNECTIONS": "1"})
	for _, curves := range [][]tls.CurveID{nil, nil, nil, {tls.X25519}} {
		cl := r.client(curves, 0)
		resp, err := cl.Get("https://" + testHost + "/")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		// a second request on the same connection is not a second connection
		resp, _ = cl.Get("https://" + testHost + "/again")
		resp.Body.Close()
		cl.CloseIdleConnections()
	}
	resp, err := http.Get("http://" + r.health + "/stats")
	if err != nil {
		t.Fatal(err)
	}
	var sn Snapshot
	json.NewDecoder(resp.Body).Decode(&sn)
	resp.Body.Close()
	if sn.Connections != 4 || sn.PostQuantum != 3 || sn.Groups["X25519MLKEM768"] != 3 || sn.Groups["X25519"] != 1 || sn.PQShare != 0.75 {
		t.Fatalf("stats %+v", sn)
	}
	r.shield.logSnapshot()
	logs := r.logs.String()
	if !strings.Contains(logs, "pq_share=75.0%") || !strings.Contains(logs, `groups="X25519MLKEM768=3 X25519=1"`) {
		t.Fatalf("counter line missing: %s", logs)
	}
	if !strings.Contains(logs, `msg=connection group=X25519MLKEM768 post_quantum=true tls="TLS 1.3"`) || strings.Contains(logs, "127.0.0.1") {
		t.Fatalf("connection lines: %s", logs)
	}
}

// ── proxying ────────────────────────────────────────────────────────────────

func TestProxySendsForwardingHeadersAndDropsForgedOnes(t *testing.T) {
	up, seen := echoUpstream(t)
	r := start(t, up.URL+"/app", nil)
	req, _ := http.NewRequest("GET", "https://"+testHost+"/cart?id=7", nil)
	req.Header.Set("X-Forwarded-For", "6.6.6.6")
	req.Header.Set("Forwarded", "for=6.6.6.6")
	req.Header.Set("X-Forwarded-Proto", "http")
	resp, err := r.client(nil, 0).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello from upstream /app/cart?id=7" || resp.Header.Get("X-Upstream") != "yes" {
		t.Fatalf("body %q headers %v", body, resp.Header)
	}
	in := <-seen
	want := map[string]string{
		"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Proto": "https", "X-Forwarded-Host": testHost,
		"Forwarded": "for=127.0.0.1;host=" + testHost + ";proto=https",
	}
	for k, v := range want {
		if got := strings.Join(in.Header.Values(k), ","); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if in.Host != testHost {
		t.Errorf("upstream saw Host %q, want the visitor's %q", in.Host, testHost)
	}
}

func TestUpstreamHostOverride(t *testing.T) {
	up, seen := echoUpstream(t)
	r := start(t, up.URL, map[string]string{"SHIELD_UPSTREAM_HOST": "legacy.internal"})
	resp, err := r.client(nil, 0).Get("https://" + testHost + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if in := <-seen; in.Host != "legacy.internal" {
		t.Fatalf("Host %q", in.Host)
	}
}

func TestForwardedValues(t *testing.T) {
	if got := forwardedFor("[2001:db8::1]:4711"); got != `"[2001:db8::1]"` {
		t.Fatal(got)
	}
	if got := forwardedHost("example.com:8443"); got != `"example.com:8443"` {
		t.Fatal(got)
	}
	if got := forwardedHost("example.com"); got != "example.com" {
		t.Fatal(got)
	}
}

func TestOtherHostsAreRefused(t *testing.T) {
	up, _ := echoUpstream(t)
	r := start(t, up.URL, nil)
	req, _ := http.NewRequest("GET", "https://"+testHost+"/", nil)
	req.Host = "someone-else.example"
	resp, err := r.client(nil, 0).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestUpstreamDownIs502(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	r := start(t, "http://"+addr, nil)
	resp, err := r.client(nil, 0).Get("https://" + testHost + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "could not reach") {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
}

func TestWebSocketUpgrade(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || r.Header.Get("X-Forwarded-Proto") != "https" {
			http.Error(w, "want an upgrade", 400)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: test\r\n\r\n")
		rw.Flush()
		line, _ := rw.ReadString('\n')
		rw.WriteString("echo " + line)
		rw.Flush()
	}))
	defer up.Close()
	r := start(t, up.URL, nil)
	conn, err := tls.Dial("tcp", r.https, &tls.Config{RootCAs: r.cert.pool, ServerName: testHost, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(conn, "GET /socket HTTP/1.1\r\nHost: "+testHost+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Upgrade") != "websocket" {
		t.Fatalf("status %d %v", resp.StatusCode, resp.Header)
	}
	io.WriteString(conn, "ping\n")
	line, err := br.ReadString('\n')
	if err != nil || line != "echo ping\n" {
		t.Fatalf("%q %v", line, err)
	}
}

func TestStreamingReachesTheVisitorAsItIsProduced(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "second\n")
	}))
	defer up.Close()
	defer close(release)
	r := start(t, up.URL, nil)
	resp, err := r.client(nil, 0).Get("https://" + testHost + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(resp.Body).ReadString('\n'); got <- line }()
	select {
	case line := <-got:
		if line != "first\n" {
			t.Fatalf("%q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first chunk was held back until the upstream finished")
	}
}

// ── :80 ─────────────────────────────────────────────────────────────────────

func TestHTTPRedirectsToHTTPS(t *testing.T) {
	up, _ := echoUpstream(t)
	r := start(t, up.URL, nil)
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	do := func(method, host string) *http.Response {
		req, _ := http.NewRequest(method, "http://"+r.http+"/basket?x=1", nil)
		req.Host = host
		resp, err := noFollow.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if resp := do("GET", testHost); resp.StatusCode != 301 || resp.Header.Get("Location") != "https://"+testHost+"/basket?x=1" {
		t.Fatalf("GET: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := do("POST", testHost+":80"); resp.StatusCode != 308 || resp.Header.Get("Location") != "https://"+testHost+"/basket?x=1" {
		t.Fatalf("POST: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := do("GET", "evil.example"); resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("other host: %d", resp.StatusCode)
	}
}

func TestACMEMode(t *testing.T) {
	up, _ := echoUpstream(t)
	vars := map[string]string{"SHIELD_DOMAINS": testHost, "SHIELD_UPSTREAM": up.URL, "SHIELD_ACME_DIR": filepath.Join(t.TempDir(), "acme")}
	cfg, err := LoadConfig(nil, env(vars), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.ACMEDir); err != nil {
		t.Fatal("the cache directory is created:", err)
	}
	tc := s.TLSConfig()
	if tc.CurvePreferences != nil || !strings.Contains(strings.Join(tc.NextProtos, ","), "acme-tls/1") || tc.GetCertificate == nil {
		t.Fatalf("ACME TLS config %+v", tc)
	}
	h := s.HTTPHandler()
	// The challenge path is answered by autocert (no token here: 404), never redirected.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://"+testHost+"/.well-known/acme-challenge/abc", nil)
	h.ServeHTTP(rec, req)
	if rec.Code == 301 || rec.Code == 308 {
		t.Fatalf("challenge redirected: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://"+testHost+"/", nil))
	if rec.Code != 301 || rec.Header().Get("Location") != "https://"+testHost+"/" {
		t.Fatalf("redirect %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// A hostname outside SHIELD_DOMAINS never gets a certificate request.
	if _, err := tc.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example"}); err == nil {
		t.Fatal("a certificate for a host outside SHIELD_DOMAINS")
	}
}

// ── upstream TLS ────────────────────────────────────────────────────────────

func TestHTTPSUpstreamIsVerifiedByDefault(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "secure upstream") }))
	defer up.Close()
	get := func(r *running) (int, string) {
		resp, err := r.client(nil, 0).Get("https://" + testHost + "/")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	if code, _ := get(start(t, up.URL, nil)); code != http.StatusBadGateway {
		t.Fatalf("an unverifiable upstream was trusted: %d", code)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.Certificate().Raw}), 0o600)
	if code, body := get(start(t, up.URL, map[string]string{"SHIELD_UPSTREAM_CA": caFile})); code != 200 || body != "secure upstream" {
		t.Fatalf("with its CA: %d %q", code, body)
	}
	r := start(t, up.URL, map[string]string{"SHIELD_UPSTREAM_INSECURE": "1"})
	if code, _ := get(r); code != 200 {
		t.Fatalf("insecure opt-out: %d", code)
	}
	if !strings.Contains(r.logs.String(), "UPSTREAM CERTIFICATE NOT VERIFIED") {
		t.Fatalf("the opt-out must warn loudly: %s", r.logs.String())
	}
}

// ── config ──────────────────────────────────────────────────────────────────

func TestConfigDefaultsAndFlags(t *testing.T) {
	cfg, err := LoadConfig(nil, env(map[string]string{"SHIELD_DOMAINS": "A.example.com, b.example.com ,a.example.com", "SHIELD_UPSTREAM": "http://app:8080"}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":443" || cfg.HTTPListen != ":80" || cfg.HealthListen != "127.0.0.1:9180" || cfg.ACMEDir != "/data/acme" || !cfg.ACME() ||
		strings.Join(cfg.Domains, ",") != "a.example.com,b.example.com" || cfg.Insecure || cfg.UpstreamTimeout != 60*time.Second {
		t.Fatalf("defaults %+v", cfg)
	}
	cfg, err = LoadConfig([]string{"-listen", ":8443", "-http-listen", "off", "-upstream", "https://app.internal"},
		env(map[string]string{"SHIELD_DOMAINS": "x.example.com", "SHIELD_UPSTREAM": "http://ignored:1", "SHIELD_LISTEN": ":9"}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8443" || cfg.HTTPListen != "" || cfg.Upstream.String() != "https://app.internal" {
		t.Fatalf("flags win over variables: %+v", cfg)
	}
}

func TestConfigValidation(t *testing.T) {
	base := map[string]string{"SHIELD_DOMAINS": "example.com", "SHIELD_UPSTREAM": "http://app:8080"}
	bad := map[string]map[string]string{
		"no upstream":              {"SHIELD_UPSTREAM": ""},
		"ftp upstream":             {"SHIELD_UPSTREAM": "ftp://app"},
		"upstream without host":    {"SHIELD_UPSTREAM": "http://"},
		"upstream with password":   {"SHIELD_UPSTREAM": "http://u:p@app"},
		"upstream with query":      {"SHIELD_UPSTREAM": "http://app/?a=1"},
		"upstream bad port":        {"SHIELD_UPSTREAM": "http://app:99999"},
		"no domains for ACME":      {"SHIELD_DOMAINS": ""},
		"wildcard":                 {"SHIELD_DOMAINS": "*.example.com"},
		"ip as domain":             {"SHIELD_DOMAINS": "192.0.2.1"},
		"no dot":                   {"SHIELD_DOMAINS": "localhost"},
		"bad label":                {"SHIELD_DOMAINS": "-bad.example.com"},
		"underscore":               {"SHIELD_DOMAINS": "a_b.example.com"},
		"cert without key":         {"SHIELD_CERT": "/c.pem"},
		"key without cert":         {"SHIELD_KEY": "/k.pem"},
		"insecure on http":         {"SHIELD_UPSTREAM_INSECURE": "true"},
		"ca on http":               {"SHIELD_UPSTREAM_CA": "/ca.pem"},
		"insecure and ca":          {"SHIELD_UPSTREAM": "https://app", "SHIELD_UPSTREAM_INSECURE": "1", "SHIELD_UPSTREAM_CA": "/ca.pem"},
		"bad listen":               {"SHIELD_LISTEN": "443"},
		"listen off":               {"SHIELD_LISTEN": "off"},
		"bad http listen":          {"SHIELD_HTTP_LISTEN": "nope"},
		"bad email":                {"SHIELD_ACME_EMAIL": "not an email"},
		"http acme url":            {"SHIELD_ACME_URL": "http://acme.example/dir"},
		"bad timeout":              {"SHIELD_UPSTREAM_TIMEOUT": "forever"},
		"timeout out of range":     {"SHIELD_UPSTREAM_TIMEOUT": "0"},
		"empty acme dir":           {"SHIELD_ACME_DIR": ""},
		"extra positional":         {"__arg": "serve"},
		"stats interval malformed": {"SHIELD_STATS_EVERY": "often"},
	}
	for name, change := range bad {
		t.Run(name, func(t *testing.T) {
			vars := map[string]string{}
			for k, v := range base {
				vars[k] = v
			}
			var args []string
			for k, v := range change {
				if k == "__arg" {
					args = append(args, v)
				} else {
					vars[k] = v
				}
			}
			if _, err := LoadConfig(args, env(vars), io.Discard); err == nil {
				t.Fatalf("accepted %v", change)
			}
		})
	}
	// Your own certificate needs no domain list.
	if _, err := LoadConfig(nil, env(map[string]string{"SHIELD_UPSTREAM": "http://app", "SHIELD_CERT": "/c", "SHIELD_KEY": "/k"}), io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestGODEBUGCannotTurnPostQuantumOff(t *testing.T) {
	for v, want := range map[string]bool{"": false, "tlsmlkem=0": true, "http2debug=1,tlsmlkem=0": true, "tlsmlkem=0,tlsmlkem=1": false, "tlsmlkem=1": false} {
		if pqDisabledByGODEBUG(v) != want {
			t.Errorf("%q", v)
		}
	}
	t.Setenv("GODEBUG", "tlsmlkem=0")
	cfg, _ := LoadConfig(nil, env(map[string]string{"SHIELD_UPSTREAM": "http://app", "SHIELD_CERT": "/c", "SHIELD_KEY": "/k"}), io.Discard)
	if _, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil || !strings.Contains(err.Error(), "tlsmlkem=0") {
		t.Fatalf("started with post-quantum off: %v", err)
	}
}

// ── subcommands ─────────────────────────────────────────────────────────────

func TestCheckCommand(t *testing.T) {
	up, _ := echoUpstream(t)
	r := start(t, up.URL, nil)
	var out bytes.Buffer
	if code := run([]string{"check", "-insecure", "-servername", testHost, r.https}, &out, io.Discard); code != checkPQ {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "key exchange   X25519MLKEM768 (hybrid post-quantum)") || !strings.Contains(out.String(), "TLS 1.3") {
		t.Fatal(out.String())
	}
	out.Reset()
	if code := run([]string{"check", r.https, "-insecure", "-classical", "-servername", testHost}, &out, io.Discard); code != checkClassical {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "key exchange   X25519 (classical)") {
		t.Fatal(out.String())
	}
	// Verified by default: the test certificate is not trusted, so no handshake.
	out.Reset()
	if code := run([]string{"check", "-servername", testHost, r.https}, &out, io.Discard); code != checkError {
		t.Fatalf("an untrusted certificate passed: %s", out.String())
	}
	if code := run([]string{"check"}, io.Discard, io.Discard); code != checkError {
		t.Fatal("no address")
	}
}

func TestHealth(t *testing.T) {
	up, _ := echoUpstream(t)
	r := start(t, up.URL, nil)
	resp, err := http.Get("http://" + r.health + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "ok\n" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	if code := healthCmd(env(map[string]string{"SHIELD_HEALTH_LISTEN": r.health}), io.Discard); code != 0 {
		t.Fatal("shield health failed")
	}
	if code := healthCmd(env(map[string]string{"SHIELD_HEALTH_LISTEN": "127.0.0.1:1"}), io.Discard); code != 1 {
		t.Fatal("shield health passed with nothing listening")
	}
	// The health port is not the front door: the proxy is not reachable through it.
	resp, _ = http.Get("http://" + r.health + "/")
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("health port served %d for /", resp.StatusCode)
	}
}

func TestRenewedCertificateFilesAreServed(t *testing.T) {
	first := makeCert(t, testHost)
	cf, err := loadCertFiles(first.certPath, first.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := cf.get(nil)
	second := makeCert(t, testHost)
	b1, _ := os.ReadFile(second.certPath)
	b2, _ := os.ReadFile(second.keyPath)
	os.WriteFile(first.certPath, b1, 0o600)
	os.WriteFile(first.keyPath, b2, 0o600)
	future := time.Now().Add(time.Minute)
	os.Chtimes(first.certPath, future, future)
	cf.checked = time.Now().Add(-time.Minute)
	b, _ := cf.get(nil)
	if bytes.Equal(a.Certificate[0], b.Certificate[0]) {
		t.Fatal("the renewed pair was not picked up")
	}
}

func TestVersionAndHelp(t *testing.T) {
	var out bytes.Buffer
	if run([]string{"version"}, &out, io.Discard) != 0 || !strings.HasPrefix(out.String(), "morrow-shield ") {
		t.Fatal(out.String())
	}
	if run([]string{"-upstream", "ftp://x"}, io.Discard, io.Discard) != 2 {
		t.Fatal("a bad config must exit 2")
	}
}
