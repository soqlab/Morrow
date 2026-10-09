package main

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, originHandler http.Handler) (*gateway, Policy) {
	t.Helper()
	origin := httptest.NewTLSServer(originHandler)
	t.Cleanup(origin.Close)
	g := &gateway{key: strings.Repeat("a", 64), instance: "test-node", configPath: filepath.Join(t.TempDir(), "policy.json")}
	// Only the test fixture replaces DNS/TLS transport. The production executable has no bypass flag.
	g.transportFactory = func() *http.Transport {
		transport := origin.Client().Transport.(*http.Transport).Clone()
		transport.TLSClientConfig.ServerName = "127.0.0.1"
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, origin.Listener.Addr().String())
		}
		return transport
	}
	p := Policy{SiteID: strings.Repeat("b", 32), Hostname: "shop.customer.com", OriginURL: "https://origin.customer.com", Version: 1, Mode: "observe", Exceptions: []Exception{}, RetentionHours: 24, MaxBodyBytes: 1048576}
	if err := g.update(canonical(p), true); err != nil {
		t.Fatal(err)
	}
	return g, p
}

func call(g *gateway, method, path, body string, authorized bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://shop.customer.com"+path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.12:4567"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authorized {
		req.Header.Set("Authorization", "Bearer "+g.key)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	return w
}

func TestObserveEnforceRollbackAndPrivacy(t *testing.T) {
	g, p := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("origin-ok")) }))
	attack := "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
	if got := call(g, "GET", attack, "", false).Code; got != 200 {
		t.Fatalf("observe blocked: %d", got)
	}
	stats := g.current.Load().stats.snapshot(24)
	if stats["matched"].(int) == 0 || stats["blocked"].(int) != 0 {
		t.Fatal(stats)
	}
	p.Version++
	p.Mode = "enforce"
	if err := g.update(canonical(p), true); err != nil {
		t.Fatal(err)
	}
	if got := call(g, "GET", attack, "", false).Code; got != 403 {
		t.Fatalf("not blocked: %d", got)
	}
	if got := call(g, "POST", "/login", "username=alice&password=TEST_PRIVATE_PASSWORD", false).Code; got != 200 {
		t.Fatalf("login failed: %d", got)
	}
	statsJSON, _ := json.Marshal(g.current.Load().stats.snapshot(24))
	for _, forbidden := range []string{"alice", "TEST_PRIVATE_PASSWORD", "/login", "192.0.2", "cookie", "Authorization"} {
		if strings.Contains(string(statsJSON), forbidden) {
			t.Fatal("sensitive metadata retained")
		}
	}
	p.Version++
	p.Mode = "observe"
	if err := g.update(canonical(p), true); err != nil {
		t.Fatal(err)
	}
	if call(g, "GET", attack, "", false).Code != 200 {
		t.Fatal("rollback did not restore observe mode")
	}
	p.Version++
	p.RetentionHours = 0
	if err := g.update(canonical(p), true); err != nil {
		t.Fatal(err)
	}
	call(g, "GET", attack, "", false)
	if g.current.Load().stats.snapshot(0)["requests"].(int) != 0 {
		t.Fatal("zero retention ignored")
	}
}

func TestInvalidUpdatesAuthAndPersistence(t *testing.T) {
	g, p := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	if call(g, "PUT", "/__airlock/policy", string(canonical(p)), false).Code != 401 {
		t.Fatal("unauthorized update allowed")
	}
	if call(g, "GET", "/__airlock/statistics", "", false).Code != 401 {
		t.Fatal("private stats exposed")
	}
	before, _ := os.ReadFile(g.configPath)
	p.Version++
	p.Mode = "disabled"
	if call(g, "PUT", "/__airlock/policy", string(canonical(p)), true).Code != 409 {
		t.Fatal("invalid WAF mode accepted")
	}
	after, _ := os.ReadFile(g.configPath)
	if string(before) != string(after) {
		t.Fatal("last known-good config was overwritten")
	}
	if g.current.Load().policy.Version != 1 {
		t.Fatal("invalid update changed runtime")
	}
	p.Mode = "observe"
	p.Version = 1
	p.RetentionHours = 0
	if g.update(canonical(p), true) == nil {
		t.Fatal("same-version policy tampering allowed")
	}
	if call(g, "DELETE", "/__airlock/statistics", "", true).Code != 204 {
		t.Fatal("purge failed")
	}
	request := httptest.NewRequest("GET", "https://other.customer.com/", nil)
	result := httptest.NewRecorder()
	g.ServeHTTP(result, request)
	if result.Code != 421 {
		t.Fatal("unknown hostname accepted")
	}
}

func TestExactExceptionAndAutomaticExpiry(t *testing.T) {
	g, p := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	p.Version++
	p.Mode = "enforce"
	// Exclude only the method rule on an exact path; do not turn off the entire WAF.
	p.Exceptions = []Exception{{RuleID: 911100, Path: "/editor", Method: "DELETE", ExpiresAt: time.Now().Add(time.Hour).Unix(), Reason: "Customer reviewed editor method"}}
	if err := g.update(canonical(p), true); err != nil {
		t.Fatal(err)
	}
	if result := call(g, "DELETE", "/editor", "", false); result.Code != 200 {
		t.Fatalf("scoped exception did not take effect: %d; rule counts: %v", result.Code, g.current.Load().stats.snapshot(24))
	}
	// Other paths must remain protected even with an exception configured.
	if call(g, "DELETE", "/account", "", false).Code != 403 {
		t.Fatal("exception leaked across paths")
	}
	p.Version++
	p.Exceptions[0].ExpiresAt = time.Now().Add(-time.Minute).Unix()
	if err := g.update(canonical(p), true); err != nil {
		t.Fatal(err)
	}
	if call(g, "DELETE", "/editor", "", false).Code != 403 {
		t.Fatal("expired exception still active")
	}
}

func TestCookiesFormsUploadsAndHeaderTrust(t *testing.T) {
	g, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("X-Forwarded-For"), "forged") || r.Header.Get("Forwarded") != "" {
			t.Error("spoofed forwarding headers reached origin")
		}
		if r.Header.Get("Cookie") != "session=TEST_COOKIE" {
			t.Error("login session lost")
		}
		body, _ := io.ReadAll(r.Body)
		if len(body) == 0 {
			t.Error("body lost")
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "TEST_NEW_COOKIE", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		w.WriteHeader(201)
	}))
	for _, contentType := range []string{"application/x-www-form-urlencoded", "application/json", "application/octet-stream"} {
		req := httptest.NewRequest("POST", "https://shop.customer.com/submit", strings.NewReader("test-body"))
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Cookie", "session=TEST_COOKIE")
		req.Header.Set("X-Forwarded-For", "forged")
		req.Header.Set("Forwarded", "for=forged")
		out := httptest.NewRecorder()
		g.ServeHTTP(out, req)
		if out.Code != 201 || !strings.Contains(out.Header().Get("Set-Cookie"), "HttpOnly") {
			t.Fatalf("compatibility failed: %d", out.Code)
		}
	}
}

func TestWebSocketUpgrade(t *testing.T) {
	g, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hash := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		connection, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer connection.Close()
		fmt.Fprintf(buffer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(hash[:]))
		buffer.Flush()
		frame := make([]byte, 10)
		if _, err := io.ReadFull(buffer, frame); err != nil {
			return
		}
		buffer.Write([]byte{0x81, 4, 'p', 'o', 'n', 'g'})
		buffer.Flush()
	}))
	server := httptest.NewTLSServer(g)
	defer server.Close()
	req, _ := http.NewRequest("GET", server.URL+"/socket", nil)
	req.Host = "shop.customer.com"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 101 {
		t.Fatalf("upgrade failed: %d", response.StatusCode)
	}
	channel, ok := response.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatal("upgrade is not bidirectional")
	}
	channel.Write([]byte{0x81, 0x84, 0, 0, 0, 0, 'p', 'i', 'n', 'g'})
	frame := make([]byte, 6)
	if _, err := io.ReadFull(channel, frame); err != nil {
		t.Fatal(err)
	}
	if string(frame[2:]) != "pong" {
		t.Fatal("websocket response lost")
	}
}

func TestPublicAddressPolicy(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "::ffff:8.8.8.8", "2001:db8::1", "224.0.0.1", "3fff::1", "2001::1", "64:ff9b::808:808", "192.88.99.1"} {
		if publicAddress(netip.MustParseAddr(value)) {
			t.Fatalf("unsafe address accepted: %s", value)
		}
	}
	if !publicAddress(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public address rejected")
	}
}

func TestBoundedStatisticsRingAndExpiry(t *testing.T) {
	s := &statistics{}
	for i := 0; i < 12000; i++ {
		s.add("requests", 0, 24)
	}
	if len(s.events) != 10000 || s.snapshot(24)["requests"].(int) != 10000 {
		t.Fatal("event window is not bounded")
	}
	s.add("blocked", 0, 24)
	counts := s.snapshot(24)
	if counts["requests"].(int) != 9999 || counts["blocked"].(int) != 1 {
		t.Fatal("ring does not retain the newest events")
	}
	for i := range s.events {
		s.events[i].at = time.Now().Add(-25 * time.Hour)
	}
	if s.snapshot(24)["requests"].(int) != 0 || len(s.events) != 0 {
		t.Fatal("expired events retained")
	}
	s.add("requests", 0, 24)
	s.clear()
	s.add("requests", 0, 0)
	if len(s.events) != 0 || s.next != 0 {
		t.Fatal("purge or zero retention failed")
	}
}

func TestOriginErrorsAreNotWAFBlocksAndBodyLimitsFailClosed(t *testing.T) {
	forwarded := 0
	g, p := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded++
		w.WriteHeader(403)
	}))
	p.Mode, p.Version, p.MaxBodyBytes = "enforce", 2, 32768
	if err := g.update(canonical(p), true); err != nil {
		t.Fatal(err)
	}
	if call(g, "GET", "/account", "", false).Code != 403 {
		t.Fatal("origin status lost")
	}
	if g.current.Load().stats.snapshot(24)["blocked"].(int) != 0 {
		t.Fatal("origin denial mislabeled as WAF blocking")
	}
	before := forwarded
	for _, chunked := range []bool{false, true} {
		req := httptest.NewRequest("POST", "https://shop.customer.com/upload", strings.NewReader(strings.Repeat("a", 32769)))
		req.Header.Set("Content-Type", "application/octet-stream")
		if chunked {
			req.ContentLength = -1
			req.TransferEncoding = []string{"chunked"}
		}
		out := httptest.NewRecorder()
		g.ServeHTTP(out, req)
		if out.Code < 400 || forwarded != before {
			t.Fatalf("oversized body reached origin: %d", out.Code)
		}
	}
	for i := 0; i < cap(g.slots); i++ {
		g.slots <- struct{}{}
	}
	if out := call(g, "GET", "/", "", false); out.Code != 503 || forwarded != before {
		t.Fatal("capacity limit bypassed filtering")
	}
	for len(g.slots) > 0 {
		<-g.slots
	}
}

func TestUnavailableOriginNeverBypasses(t *testing.T) {
	g, p := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	g.transportFactory = func() *http.Transport {
		tr := newTransport()
		tr.DialContext = func(context.Context, string, string) (net.Conn, error) { return nil, fmt.Errorf("fixture unavailable") }
		return tr
	}
	p.Version++
	if err := g.update(canonical(p), true); err != nil {
		t.Fatal(err)
	}
	if out := call(g, "GET", "/", "", false); out.Code != 502 || !strings.Contains(out.Body.String(), "no protection bypass") {
		t.Fatal("unsafe failure response")
	}
	if g.current.Load().stats.snapshot(24)["upstream_errors"].(int) != 1 {
		t.Fatal("missing real upstream error count")
	}
}

func TestSharedPolicyLockAndReplicaVersionBoundary(t *testing.T) {
	g, p := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	replica := &gateway{key: g.key, instance: "second", configPath: g.configPath, transportFactory: g.transportFactory}
	if err := replica.update(canonical(p), false); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockPolicy(g.configPath)
	if err != nil {
		t.Fatal(err)
	}
	p.Version++
	if err := g.update(canonical(p), true); err == nil {
		t.Fatal("cross-process lock ignored")
	}
	unlock()
	oldStats := g.current.Load().stats
	if err := g.update(canonical(p), true); err != nil {
		t.Fatal(err)
	}
	oldStats.add("blocked", 0, 24)
	if g.current.Load().stats.snapshot(24)["blocked"].(int) != 0 {
		t.Fatal("old in-flight request leaked into new version")
	}
	p.Mode = "enforce"
	if err := replica.update(canonical(p), true); err == nil {
		t.Fatal("stale replica overwrote same-version shared policy")
	}
	raw, _ := os.ReadFile(g.configPath)
	if err := replica.update(raw, false); err != nil {
		t.Fatal(err)
	}
	if replica.current.Load().hash != g.current.Load().hash {
		t.Fatal("replica did not converge")
	}
	if err := replica.update([]byte("broken JSON"), false); err == nil || replica.current.Load().policy.Version != 2 {
		t.Fatal("invalid reload displaced last known-good policy")
	}
}
