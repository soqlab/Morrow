// Airlock's isolated data plane uses Coraza/OWASP CRS and Go's HTTP reverse proxy.
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	crs "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/felixge/httpsnoop"
)

type Exception struct {
	RuleID    int    `json:"rule_id"`
	Path      string `json:"path"`
	Method    string `json:"method"`
	ExpiresAt int64  `json:"expires_at"`
	Reason    string `json:"reason"`
}

type Policy struct {
	SiteID         string      `json:"site_id"`
	Hostname       string      `json:"hostname"`
	OriginURL      string      `json:"origin_url"`
	Version        int         `json:"version"`
	Mode           string      `json:"mode"`
	Exceptions     []Exception `json:"exceptions"`
	RetentionHours int         `json:"retention_hours"`
	MaxBodyBytes   int64       `json:"max_body_bytes"`
}

type record struct {
	at   time.Time
	kind string
	rule int
}
type statistics struct {
	mu     sync.Mutex
	events []record
	next   int
}

func (s *statistics) add(kind string, rule int, hours int) {
	if hours == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	event := record{time.Now(), kind, rule}
	if len(s.events) < 10000 {
		s.events = append(s.events, event)
	} else {
		s.events[s.next] = event
		s.next = (s.next + 1) % len(s.events)
	}
}

func (s *statistics) snapshot(hours int) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	events := make([]record, 0, len(s.events))
	out := map[string]any{"requests": 0, "blocked": 0, "matched": 0, "upstream_errors": 0}
	rules := map[string]int{}
	for i := range s.events {
		event := s.events[(s.next+i)%len(s.events)]
		if hours == 0 || event.at.Before(cutoff) {
			continue
		}
		events = append(events, event)
		out[event.kind] = out[event.kind].(int) + 1
		if event.rule != 0 {
			rules[strconv.Itoa(event.rule)]++
		}
	}
	s.events = events
	s.next = 0
	out["rule_counts"] = rules
	return out
}

func (s *statistics) clear() { s.mu.Lock(); s.events = nil; s.next = 0; s.mu.Unlock() }

type runtimePolicy struct {
	policy    Policy
	hash      string
	handler   http.Handler
	transport *http.Transport
	selfTest  bool
	stats     *statistics
}

type gateway struct {
	current          atomic.Pointer[runtimePolicy]
	mu               sync.Mutex
	key              string
	instance         string
	configPath       string
	limitsOnce       sync.Once
	slots            chan struct{}
	transportFactory func() *http.Transport
}

var safeHost = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
var safePath = regexp.MustCompile(`^/[A-Za-z0-9/_.-]*$`)
var safeID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var safeNonce = regexp.MustCompile(`^[a-f0-9]{48}$`)

func canonical(p Policy) []byte {
	raw, _ := json.Marshal(p)
	var value map[string]any
	_ = json.Unmarshal(raw, &value)
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
	return bytes.TrimSpace(out.Bytes())
}

func validate(p Policy) error {
	upstream, err := url.Parse(p.OriginURL)
	if err != nil || upstream.Scheme != "https" || upstream.User != nil || upstream.Port() != "" || upstream.RawQuery != "" || upstream.Fragment != "" || upstream.Path != "" {
		return errors.New("origin must be an HTTPS hostname without credentials, path, or port")
	}
	for _, host := range []string{p.Hostname, upstream.Hostname()} {
		if !safeHost.MatchString(host) || !strings.Contains(host, ".") || strings.Contains(host, "..") || net.ParseIP(host) != nil {
			return errors.New("invalid DNS hostname")
		}
	}
	if upstream.Hostname() == p.Hostname || !safeID.MatchString(p.SiteID) || p.Version < 1 || (p.Mode != "observe" && p.Mode != "enforce") {
		return errors.New("invalid site, version, routing loop, or mode")
	}
	if p.RetentionHours < 0 || p.RetentionHours > 24 || p.MaxBodyBytes < 32768 || p.MaxBodyBytes > 8388608 || len(p.Exceptions) > 20 {
		return errors.New("invalid retention, body limit, or exception count")
	}
	for _, exception := range p.Exceptions {
		if exception.RuleID < 900000 || exception.RuleID > 999999 || exception.RuleID == 949110 || exception.RuleID == 959100 || exception.RuleID == 980130 ||
			!safePath.MatchString(exception.Path) || strings.Contains(exception.Path, "..") || strings.Contains(exception.Path, "//") || strings.HasPrefix(exception.Path, "/__airlock") ||
			!regexp.MustCompile(`^(GET|HEAD|POST|PUT|PATCH|DELETE)$`).MatchString(exception.Method) || exception.ExpiresAt > time.Now().Add(7*24*time.Hour).Unix() || len(exception.Reason) < 8 {
			return errors.New("invalid scoped rule exception")
		}
	}
	return nil
}

func publicAddress(address netip.Addr) bool {
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsUnspecified() || address.Is4In6() {
		return false
	}
	if address.Is6() && !netip.MustParsePrefix("2000::/3").Contains(address) {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "3ffe::/16", "3fff::/20"} {
		if netip.MustParsePrefix(cidr).Contains(address) {
			return false
		}
	}
	return true
}

func newTransport() *http.Transport {
	return &http.Transport{
		Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout: 30 * time.Second, MaxIdleConnsPerHost: 32, MaxConnsPerHost: 128,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || port != "443" {
				return nil, errors.New("invalid origin destination")
			}
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil || len(ips) == 0 || len(ips) > 32 {
				return nil, errors.New("origin DNS unavailable")
			}
			for _, ip := range ips {
				if !publicAddress(ip) {
					return nil, errors.New("non-public origin blocked")
				}
			}
			// Pin the validated address, without a second resolver lookup or proxy environment variables.
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		},
	}
}

func (g *gateway) build(p Policy) (*runtimePolicy, error) {
	if err := validate(p); err != nil {
		return nil, err
	}
	engine := "DetectionOnly"
	if p.Mode == "enforce" {
		engine = "On"
	}
	directives := fmt.Sprintf(`
Include @coraza.conf-recommended
SecRuleEngine %s
SecRequestBodyAccess On
SecRequestBodyLimit %d
SecRequestBodyInMemoryLimit %d
SecRequestBodyLimitAction Reject
SecResponseBodyAccess Off
SecAuditEngine Off
SecDebugLogLevel 0
Include @crs-setup.conf.example
`, engine, p.MaxBodyBytes, p.MaxBodyBytes)
	for i, exception := range p.Exceptions {
		// TIME_EPOCH enforces expiry per request, including long-lived gateway processes.
		directives += fmt.Sprintf(`SecRule REQUEST_FILENAME "@streq %s" "id:%d,phase:1,pass,nolog,chain"
SecRule REQUEST_METHOD "@streq %s" "chain"
SecRule TIME_EPOCH "@lt %d" "ctl:ruleRemoveById=%d"
`, exception.Path, 11000+i, exception.Method, exception.ExpiresAt, exception.RuleID)
	}
	directives += "Include @owasp_crs/*.conf\n"
	var live atomic.Bool
	var testMatches atomic.Int64
	stats := &statistics{}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(crs.FS).WithDirectives(directives).
		WithErrorCallback(func(m types.MatchedRule) {
			if !live.Load() {
				testMatches.Add(1)
				return
			}
			// Never call ErrorLog(): matched data can include passwords, cookies, or request bodies.
			stats.add("matched", m.Rule().ID(), p.RetentionHours)
		}))
	if err != nil {
		return nil, errors.New("WAF configuration did not compile")
	}
	recorder := httptest.NewRecorder()
	probe := httptest.NewRequest("GET", "https://"+p.Hostname+"/__airlock/selftest?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil)
	probe.RemoteAddr = "192.0.2.10:1234"
	txhttp.WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(recorder, probe)
	wanted := 204
	if p.Mode == "enforce" {
		wanted = 403
	}
	if recorder.Code != wanted || testMatches.Load() == 0 {
		return nil, fmt.Errorf("WAF self-test failed: status=%d", recorder.Code)
	}
	live.Store(true)
	factory := g.transportFactory
	if factory == nil {
		factory = newTransport
	}
	transport := factory()
	upstream, _ := url.Parse(p.OriginURL)
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstream)
			r.Out.Header.Del("Forwarded")
			r.Out.Header.Del("X-Real-IP")
			r.SetXForwarded()
		},
		ErrorLog: log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			stats.add("upstream_errors", 0, p.RetentionHours)
			http.Error(w, "Origin unavailable; no protection bypass performed", http.StatusBadGateway)
		},
	}
	sum := sha256.Sum256(canonical(p))
	proxied := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if state, ok := r.Context().Value(requestStateKey{}).(*requestState); ok {
			state.forwarded = true
		}
		proxy.ServeHTTP(w, r)
	})
	return &runtimePolicy{p, hex.EncodeToString(sum[:]), txhttp.WrapHandler(waf, proxied), transport, true, stats}, nil
}

type requestStateKey struct{}
type requestState struct{ forwarded bool }

func decode(data []byte) (Policy, error) {
	var p Policy
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&p)
	if err == nil && decoder.Decode(new(any)) != io.EOF {
		err = errors.New("trailing configuration data")
	}
	return p, err
}

func (g *gateway) update(data []byte, persist bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	p, err := decode(data)
	if err != nil {
		return errors.New("invalid configuration JSON")
	}
	if persist {
		// Serialize all writers sharing the volume, not just handlers in this process.
		unlock, err := lockPolicy(g.configPath)
		if err != nil {
			return err
		}
		defer unlock()
		if raw, err := os.ReadFile(g.configPath); err == nil {
			disk, err := decode(raw)
			if err != nil || disk.SiteID != p.SiteID || disk.Hostname != p.Hostname || disk.OriginURL != p.OriginURL ||
				(p.Version <= disk.Version && !bytes.Equal(canonical(p), canonical(disk))) {
				return errors.New("shared policy changed; refresh before publishing")
			}
		} else if !os.IsNotExist(err) {
			return errors.New("cannot read shared policy")
		}
	}
	old := g.current.Load()
	if old != nil {
		if p.Hostname != old.policy.Hostname || p.SiteID != old.policy.SiteID || p.OriginURL != old.policy.OriginURL {
			return errors.New("site binding cannot change")
		}
		if p.Version <= old.policy.Version {
			if bytes.Equal(canonical(p), canonical(old.policy)) {
				return nil
			}
			return errors.New("configuration version is stale")
		}
	}
	next, err := g.build(p)
	if err != nil {
		return err
	}
	if persist {
		tmp, err := os.CreateTemp(filepath.Dir(g.configPath), ".policy-*")
		if err != nil {
			return errors.New("cannot persist policy")
		}
		name := tmp.Name()
		defer os.Remove(name)
		_, err = tmp.Write(canonical(p))
		if err == nil {
			err = tmp.Sync()
		}
		closeErr := tmp.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Rename(name, g.configPath)
		}
		if err != nil {
			next.transport.CloseIdleConnections()
			return errors.New("cannot atomically persist policy")
		}
	}
	g.current.Store(next)
	// Each version owns its metrics, so old in-flight requests cannot contaminate a new policy.
	if old != nil {
		old.transport.CloseIdleConnections()
	}
	return nil
}

func (g *gateway) authorized(r *http.Request) bool {
	return hmac.Equal([]byte(r.Header.Get("Authorization")), []byte("Bearer "+g.key))
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	active := g.current.Load()
	if active == nil {
		http.Error(w, "Gateway not ready", 503)
		return
	}
	host := r.Host
	if strings.HasSuffix(host, ":443") {
		host = strings.TrimSuffix(host, ":443")
	}
	if host != active.policy.Hostname {
		http.Error(w, "Unknown hostname", 421)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/__airlock/") {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/__airlock/challenge" && r.Method == "GET" {
			nonce := r.URL.Query().Get("nonce")
			if !safeNonce.MatchString(nonce) {
				http.Error(w, "Invalid challenge", 400)
				return
			}
			payload, _ := json.Marshal(map[string]any{"nonce": nonce, "time": time.Now().Unix(), "site_id": active.policy.SiteID,
				"config_hash": active.hash, "mode": active.policy.Mode, "instance": g.instance, "waf_self_test": active.selfTest})
			mac := hmac.New(sha256.New, []byte(g.key))
			mac.Write(payload)
			_ = json.NewEncoder(w).Encode(map[string]string{"payload": base64.StdEncoding.EncodeToString(payload), "signature": hex.EncodeToString(mac.Sum(nil))})
			return
		}
		if !g.authorized(r) {
			http.Error(w, "Unauthorized", 401)
			return
		}
		switch {
		case r.URL.Path == "/__airlock/policy" && r.Method == "PUT":
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32768))
			if err != nil {
				http.Error(w, "Policy too large", 413)
				return
			}
			if err = g.update(body, true); err != nil {
				http.Error(w, err.Error(), 409)
				return
			}
			w.Write([]byte(`{"applied":true}`))
		case r.URL.Path == "/__airlock/statistics" && r.Method == "GET":
			stats := active.stats.snapshot(active.policy.RetentionHours)
			stats["config_hash"], stats["instance"] = active.hash, g.instance
			_ = json.NewEncoder(w).Encode(stats)
		case r.URL.Path == "/__airlock/statistics" && r.Method == "DELETE":
			active.stats.clear()
			w.WriteHeader(204)
		default:
			http.NotFound(w, r)
		}
		return
	}
	g.limitsOnce.Do(func() { g.slots = make(chan struct{}, 16) })
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Gateway at capacity; no protection bypass performed", 503)
		return
	}
	active.stats.add("requests", 0, active.policy.RetentionHours)
	if r.ContentLength > active.policy.MaxBodyBytes {
		http.Error(w, "Request body too large", 413)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, active.policy.MaxBodyBytes)
	state := &requestState{}
	r = r.WithContext(context.WithValue(r.Context(), requestStateKey{}, state))
	metrics := httpsnoop.CaptureMetrics(active.handler, w, r)
	if metrics.Code == 403 && !state.forwarded && active.policy.Mode == "enforce" {
		active.stats.add("blocked", 0, active.policy.RetentionHours)
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func main() {
	key, err := os.ReadFile(env("AIRLOCK_SECRET_FILE", "/secrets/gateway.secret"))
	if err != nil || len(strings.TrimSpace(string(key))) < 64 {
		log.Fatal("A provisioned gateway secret file is required")
	}
	g := &gateway{key: strings.TrimSpace(string(key)), instance: env("HOSTNAME", "gateway"), configPath: env("AIRLOCK_POLICY_FILE", "/state/policy.json")}
	raw, err := os.ReadFile(g.configPath)
	if err != nil {
		log.Fatal("Policy file is required")
	}
	if err := g.update(raw, false); err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Replicas share an atomic policy file. Invalid updates retain the last known-good policy.
				if data, err := os.ReadFile(g.configPath); err == nil {
					_ = g.update(data, false)
				}
				active := g.current.Load()
				active.stats.snapshot(active.policy.RetentionHours)
			}
		}
	}()
	server := &http.Server{Addr: ":8443", Handler: g, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 45 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32768,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ErrorLog: log.New(io.Discard, "", 0)}
	go func() {
		<-ctx.Done()
		shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_ = server.Shutdown(shutdown)
	}()
	log.Print("Airlock gateway starting; request payload logging disabled")
	if err := server.ListenAndServeTLS(env("AIRLOCK_TLS_CERT", "/certs/fullchain.pem"), env("AIRLOCK_TLS_KEY", "/certs/privkey.pem")); err != nil && err != http.ErrServerClosed {
		log.Fatal("TLS gateway could not start")
	}
}
