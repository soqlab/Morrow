package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is everything Shield needs. It comes from environment variables and flags only (a flag
// wins over its variable); there is no config file and nothing is read from the network.
type Config struct {
	Domains         []string      // SHIELD_DOMAINS: comma-separated hostnames Shield answers for
	Upstream        *url.URL      // SHIELD_UPSTREAM: http:// or https:// address of the site or app behind Shield
	UpstreamHost    string        // SHIELD_UPSTREAM_HOST: Host header sent upstream; empty keeps the visitor's
	UpstreamCA      string        // SHIELD_UPSTREAM_CA: PEM file of extra CAs trusted for an https upstream
	UpstreamTimeout time.Duration // SHIELD_UPSTREAM_TIMEOUT: how long to wait for the upstream's response headers
	Insecure        bool          // SHIELD_UPSTREAM_INSECURE: skip verifying an https upstream's certificate
	CertFile        string        // SHIELD_CERT: your own certificate chain (PEM)
	KeyFile         string        // SHIELD_KEY: its private key (PEM)
	ACMEDir         string        // SHIELD_ACME_DIR: where automatic certificates are cached (a volume)
	ACMEEmail       string        // SHIELD_ACME_EMAIL: optional contact for the certificate authority
	ACMEURL         string        // SHIELD_ACME_URL: ACME directory; empty is Let's Encrypt production
	Listen          string        // SHIELD_LISTEN: the HTTPS address (default :443)
	HTTPListen      string        // SHIELD_HTTP_LISTEN: HTTP address for the redirect and ACME (default :80; "off" disables)
	HealthListen    string        // SHIELD_HEALTH_LISTEN: local address of /healthz and /stats (default 127.0.0.1:9180)
	StatsEvery      time.Duration // SHIELD_STATS_EVERY: how often the key-exchange counters are logged (0 = never)
	LogConnections  bool          // SHIELD_LOG_CONNECTIONS: one log line per connection (group and TLS version, no addresses)
}

// ACME reports whether certificates come from automatic ACME rather than files.
func (c *Config) ACME() bool { return c.CertFile == "" && c.KeyFile == "" }

type envLookup func(string) (string, bool)

// LoadConfig reads the environment (through lookup) and then the flags in args.
func LoadConfig(args []string, lookup envLookup, stderr io.Writer) (*Config, error) {
	get := func(key, fallback string) string {
		if v, ok := lookup(key); ok {
			return strings.TrimSpace(v)
		}
		return fallback
	}
	fs := flag.NewFlagSet("shield", flag.ContinueOnError)
	fs.SetOutput(stderr)
	domains := fs.String("domains", get("SHIELD_DOMAINS", ""), "comma-separated hostnames to serve (SHIELD_DOMAINS)")
	upstream := fs.String("upstream", get("SHIELD_UPSTREAM", ""), "http:// or https:// address of the site behind Shield (SHIELD_UPSTREAM)")
	upHost := fs.String("upstream-host", get("SHIELD_UPSTREAM_HOST", ""), "Host header sent upstream; empty keeps the visitor's (SHIELD_UPSTREAM_HOST)")
	upCA := fs.String("upstream-ca", get("SHIELD_UPSTREAM_CA", ""), "PEM file of CAs to trust for an https upstream (SHIELD_UPSTREAM_CA)")
	upTimeout := fs.String("upstream-timeout", get("SHIELD_UPSTREAM_TIMEOUT", "60s"), "wait this long for upstream response headers (SHIELD_UPSTREAM_TIMEOUT)")
	insecure := fs.Bool("insecure-skip-upstream-verify", boolEnv(get("SHIELD_UPSTREAM_INSECURE", "")), "DANGEROUS: do not verify an https upstream's certificate (SHIELD_UPSTREAM_INSECURE=1)")
	cert := fs.String("cert", get("SHIELD_CERT", ""), "certificate chain PEM file, instead of automatic ACME (SHIELD_CERT)")
	key := fs.String("key", get("SHIELD_KEY", ""), "private key PEM file for -cert (SHIELD_KEY)")
	acmeDir := fs.String("acme-dir", get("SHIELD_ACME_DIR", "/data/acme"), "cache directory for automatic certificates (SHIELD_ACME_DIR)")
	acmeEmail := fs.String("acme-email", get("SHIELD_ACME_EMAIL", ""), "optional contact email for the certificate authority (SHIELD_ACME_EMAIL)")
	acmeURL := fs.String("acme-url", get("SHIELD_ACME_URL", ""), "ACME directory URL; empty is Let's Encrypt (SHIELD_ACME_URL)")
	listen := fs.String("listen", get("SHIELD_LISTEN", ":443"), "HTTPS listen address (SHIELD_LISTEN)")
	httpListen := fs.String("http-listen", get("SHIELD_HTTP_LISTEN", ":80"), `HTTP listen address for the redirect and ACME, or "off" (SHIELD_HTTP_LISTEN)`)
	health := fs.String("health-listen", get("SHIELD_HEALTH_LISTEN", "127.0.0.1:9180"), `local address for /healthz and /stats, or "off" (SHIELD_HEALTH_LISTEN)`)
	statsEvery := fs.String("stats-every", get("SHIELD_STATS_EVERY", "15m"), "log the key-exchange counters this often; 0 never (SHIELD_STATS_EVERY)")
	logConns := fs.Bool("log-connections", boolEnv(get("SHIELD_LOG_CONNECTIONS", "")), "one log line per connection: group and TLS version, never addresses (SHIELD_LOG_CONNECTIONS=1)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q (Shield is configured with flags and SHIELD_* variables)", fs.Arg(0))
	}

	c := &Config{
		UpstreamHost: *upHost, UpstreamCA: *upCA, Insecure: *insecure,
		CertFile: *cert, KeyFile: *key, ACMEDir: *acmeDir, ACMEEmail: *acmeEmail, ACMEURL: *acmeURL,
		Listen: *listen, HTTPListen: off(*httpListen), HealthListen: off(*health), LogConnections: *logConns,
	}
	var err error
	if c.Domains, err = parseDomains(*domains); err != nil {
		return nil, err
	}
	if c.Upstream, err = parseUpstream(*upstream); err != nil {
		return nil, err
	}
	if c.UpstreamTimeout, err = parseDuration("upstream timeout", *upTimeout, time.Second, time.Hour); err != nil {
		return nil, err
	}
	if c.StatsEvery, err = parseDuration("stats interval", *statsEvery, 0, 7*24*time.Hour); err != nil {
		return nil, err
	}
	return c, c.validate()
}

func off(v string) string {
	if strings.EqualFold(v, "off") || v == "" {
		return ""
	}
	return v
}

func boolEnv(v string) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	return err == nil && b
}

func parseDuration(what, v string, min, max time.Duration) (time.Duration, error) {
	if v == "0" {
		if min == 0 {
			return 0, nil
		}
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s %q: use a duration such as 30s or 15m", what, v)
	}
	if d < min || d > max {
		return 0, fmt.Errorf("%s %s is out of range (%s to %s)", what, d, min, max)
	}
	return d, nil
}

// parseDomains accepts "a.example, b.example" and returns lowercase, de-duplicated hostnames.
func parseDomains(v string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, d := range strings.Split(v, ",") {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d == "" {
			continue
		}
		if err := validHostname(d); err != nil {
			return nil, err
		}
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out, nil
}

func validHostname(d string) error {
	if len(d) > 253 {
		return fmt.Errorf("domain %q is longer than 253 characters", d)
	}
	if net.ParseIP(d) != nil {
		return fmt.Errorf("domain %q is an IP address: certificates from ACME need a hostname", d)
	}
	if strings.HasPrefix(d, "*.") {
		return fmt.Errorf("domain %q is a wildcard: list each hostname (automatic certificates cannot be wildcards here)", d)
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return fmt.Errorf("domain %q needs a dot (for example example.com)", d)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("domain %q has an empty or malformed label", d)
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("domain %q has %q: use letters, digits and hyphens (punycode for other scripts)", d, r)
			}
		}
	}
	return nil
}

func parseUpstream(v string) (*url.URL, error) {
	if v == "" {
		return nil, errors.New("SHIELD_UPSTREAM is required: the address of the site behind Shield, for example http://host.docker.internal:8080")
	}
	u, err := url.Parse(v)
	if err != nil {
		return nil, fmt.Errorf("SHIELD_UPSTREAM %q is not a URL: %v", v, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("SHIELD_UPSTREAM %q must start with http:// or https://", v)
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("SHIELD_UPSTREAM %q has no host", v)
	}
	if u.User != nil {
		return nil, errors.New("SHIELD_UPSTREAM must not carry a user name or password")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("SHIELD_UPSTREAM %q must not have a query or fragment", v)
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("SHIELD_UPSTREAM %q has an invalid port", v)
		}
	}
	return u, nil
}

func validAddr(what, a string) error {
	if a == "" {
		return nil
	}
	if _, p, err := net.SplitHostPort(a); err != nil || p == "" {
		return fmt.Errorf("%s %q: use host:port or :port", what, a)
	}
	return nil
}

func (c *Config) validate() error {
	if (c.CertFile == "") != (c.KeyFile == "") {
		return errors.New("SHIELD_CERT and SHIELD_KEY go together: set both, or neither for automatic certificates")
	}
	if c.ACME() {
		if len(c.Domains) == 0 {
			return errors.New("SHIELD_DOMAINS is required for automatic certificates (or give SHIELD_CERT and SHIELD_KEY)")
		}
		if c.ACMEDir == "" {
			return errors.New("SHIELD_ACME_DIR is required for automatic certificates: a directory on a volume, so certificates survive a restart")
		}
		if c.ACMEEmail != "" && (!strings.Contains(c.ACMEEmail, "@") || strings.ContainsAny(c.ACMEEmail, " \t\r\n")) {
			return fmt.Errorf("SHIELD_ACME_EMAIL %q is not an email address", c.ACMEEmail)
		}
		if c.ACMEURL != "" {
			if u, err := url.Parse(c.ACMEURL); err != nil || u.Scheme != "https" || u.Host == "" {
				return fmt.Errorf("SHIELD_ACME_URL %q must be an https:// URL", c.ACMEURL)
			}
		}
	}
	if c.Listen == "" {
		return errors.New("SHIELD_LISTEN cannot be off: it is the HTTPS front door")
	}
	for what, a := range map[string]string{"SHIELD_LISTEN": c.Listen, "SHIELD_HTTP_LISTEN": c.HTTPListen, "SHIELD_HEALTH_LISTEN": c.HealthListen} {
		if err := validAddr(what, a); err != nil {
			return err
		}
	}
	if c.Upstream.Scheme != "https" && (c.Insecure || c.UpstreamCA != "") {
		return errors.New("SHIELD_UPSTREAM_INSECURE and SHIELD_UPSTREAM_CA apply only to an https:// upstream")
	}
	if c.Insecure && c.UpstreamCA != "" {
		return errors.New("choose one: SHIELD_UPSTREAM_CA (verify against your CA) or SHIELD_UPSTREAM_INSECURE (no verification)")
	}
	return nil
}

func lookupOS(k string) (string, bool) { return os.LookupEnv(k) }
