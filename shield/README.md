# Morrow Shield

A quantum-safe front door for a website or an old app, in one command.

Shield is one small program. It answers HTTPS for your domain, agrees a **hybrid post-quantum key
exchange (X25519MLKEM768)** with every visitor whose browser supports it (current Chrome, Edge,
Firefox and Safari do), still serves older clients with classical TLS, and passes each request on to
your site or app unchanged. Your app does not need to change.

It is part of [Morrow](../README.md). When Morrow finds that a site is not quantum-safe and there is
no one-click fix at its DNS provider, Make it safe offers Shield, with the command below pre-filled
for that domain.

## Run it

You need a server where you can run Docker, with ports 80 and 443 free and reachable from the
internet, and DNS for your domain pointing at that server.

```sh
docker run -d --name morrow-shield --restart unless-stopped \
  -p 443:8443 -p 80:8080 --read-only --cap-drop ALL \
  --add-host host.docker.internal:host-gateway -v morrow-shield:/data \
  -e SHIELD_DOMAINS=example.com \
  -e SHIELD_UPSTREAM=http://host.docker.internal:8080 \
  ghcr.io/soqlab/morrow-shield:0.1
```

- `SHIELD_DOMAINS`: your hostname(s), comma-separated (`example.com,www.example.com`).
- `SHIELD_UPSTREAM`: where your site really is. `host.docker.internal:8080` is port 8080 on the same
  machine; use your app's port, or another address such as `http://10.0.0.5:3000` or
  `https://old-server.internal`.

The first visit to each name gets a certificate from Let's Encrypt automatically (TLS-ALPN-01 on
443 or HTTP-01 on 80), stored in the `morrow-shield` volume so a restart does not ask again. Using
automatic certificates means accepting the certificate authority's subscriber agreement.

Or with Compose: copy [`compose.yml`](compose.yml), change `SHIELD_DOMAINS` and `SHIELD_UPSTREAM`,
then `docker compose up -d`.

### Check it

```sh
docker exec morrow-shield shield check example.com
```

```
shield check example.com:443
  offered        X25519MLKEM768 and classical groups, as a current browser does
  key exchange   X25519MLKEM768 (hybrid post-quantum)
  TLS version    TLS 1.3
  ...
  verdict        quantum-safe: the server chose a post-quantum key exchange
```

`shield check` works against any server (`shield check other-site.com:443`), exits 0 for
post-quantum, 2 for classical and 1 when there is no handshake. `-classical` offers only classical
groups, to see what an old client gets. Morrow's own check (`/r/<domain>`) then shows the same
answer from the outside, and the signed proof.

## DNS

Point the A (and AAAA, if you have IPv6) record for each name in `SHIELD_DOMAINS` at the server
running Shield. If the site is on a CDN, Shield is not the right tool: turn on post-quantum at the
CDN instead (Morrow's Make it safe has the setting for each one). Certificates are issued only after
DNS points at Shield, because the certificate authority connects to it to check.

If your site already listens on 80 and 443 on this machine, move it to another port first (or run it
over plain HTTP on, say, 8080) and give that address as `SHIELD_UPSTREAM`.

## Configuration

Environment variables, or the flag after each one (a flag wins). There is no config file.

| Variable | Default | |
|---|---|---|
| `SHIELD_DOMAINS` | | Hostnames to serve. Required for automatic certificates. Requests for other names get 421. |
| `SHIELD_UPSTREAM` | | `http://` or `https://` address of your site. Required. A path is a prefix (`http://app/legacy`). |
| `SHIELD_CERT`, `SHIELD_KEY` | | Your own certificate chain and key (PEM) instead of automatic ones. Re-read when they change on disk. Must be readable by user 65532 in the image. |
| `SHIELD_ACME_DIR` | `/data/acme` | Certificate cache. Put it on a volume. |
| `SHIELD_ACME_EMAIL` | | Optional contact for the certificate authority (expiry notices). |
| `SHIELD_ACME_URL` | Let's Encrypt | Another ACME directory, for example Let's Encrypt staging. |
| `SHIELD_LISTEN` | `:443` (image: `:8443`) | HTTPS. |
| `SHIELD_HTTP_LISTEN` | `:80` (image: `:8080`) | HTTP: redirect to HTTPS and ACME challenges. `off` disables. |
| `SHIELD_HEALTH_LISTEN` | `127.0.0.1:9180` | Local only: `/healthz`, and `/stats` (the counters as JSON). `off` disables. |
| `SHIELD_UPSTREAM_HOST` | the visitor's | Host header sent upstream. |
| `SHIELD_UPSTREAM_TIMEOUT` | `60s` | Wait this long for your app's response headers. |
| `SHIELD_UPSTREAM_CA` | | PEM file of a private CA, for an `https://` upstream with an internal certificate. |
| `SHIELD_UPSTREAM_INSECURE` | off | **Dangerous.** Do not verify an `https://` upstream's certificate. Shield logs a loud warning at start and every stats interval. Prefer `SHIELD_UPSTREAM_CA`. |
| `SHIELD_STATS_EVERY` | `15m` | Log the key-exchange counters this often (`0`: only at shutdown). |
| `SHIELD_LOG_CONNECTIONS` | off | One log line per connection: the group and TLS version, never addresses. |

### What reaches your app

- `X-Forwarded-For` (the visitor's address), `X-Forwarded-Proto: https`, `X-Forwarded-Host`, and the
  standard `Forwarded: for=...;host=...;proto=https` (RFC 7239). Shield is the first hop: any of
  these headers the visitor sent are dropped, so they cannot be forged.
- The visitor's `Host` header, unless `SHIELD_UPSTREAM_HOST` is set.
- WebSocket upgrades, server-sent events and other streams pass straight through; every write is
  flushed to the visitor as it arrives. HTTP/2 to visitors; HTTP/2 or 1.1 to the upstream.

### Safe defaults

10 s to send request headers, 64 KiB of request headers, 120 s idle keep-alive, 10 s to connect to
the upstream, 1 MiB of upstream response headers. No read or write deadline on bodies, so uploads,
downloads, streams and WebSockets are not cut off. TLS 1.2 is the minimum; Go's TLS stack prefers
TLS 1.3 and offers only AEAD cipher suites with forward secrecy. Shield sets no HSTS header; add it
in your app once you are sure HTTPS stays.

## The post-quantum share

Shield counts the key-exchange group of every handshake: no addresses, nothing per visitor. It logs
a line like this every `SHIELD_STATS_EVERY` and at shutdown:

```
level=INFO msg="key exchange" connections=1840 post_quantum=1712 pq_share=93.0% groups="X25519MLKEM768=1712 X25519=121 CurveP256=7"
```

`docker exec morrow-shield shield health` is the container's health check; `/stats` on the local
health port has the same counters as JSON.

## How it compares

| | Morrow Shield | Cloudflare | Quantum Airlock (`gateway/`) |
|---|---|---|---|
| What it is | One binary or container on your server | A CDN in front of your DNS | Morrow's enterprise gateway: reverse proxy, Coraza WAF, HAProxy pair, signed policy |
| Post-quantum to visitors | Yes (X25519MLKEM768) | Yes, on proxied hostnames | Yes |
| Your traffic passes through | Your own server only | Cloudflare | Your own servers |
| Needs | Docker, ports 80/443, DNS at your server | Moving DNS to Cloudflare, or a proxied record | A deployment, a policy, an operator |
| Caching, DDoS, WAF | None | Yes | WAF, rate limits |
| Cost | Free, open source | Cloudflare's plans | Free, open source |

Shield is the smallest thing that makes a site quantum-safe without moving it anywhere. If you need
a WAF, signed policy and a failover pair, use the Airlock; if you want a CDN, use one that offers
post-quantum by default.

## Limits

- **It protects the leg from the visitor to Shield.** Shield to your app is plain HTTP when
  `SHIELD_UPSTREAM` is `http://`; keep that on the same machine or a private network. With an
  `https://` upstream, Shield's client also offers X25519MLKEM768, but that leg is post-quantum only
  if your app's TLS supports it.
- Post-quantum key exchange protects recorded traffic from being decrypted later ("harvest now,
  decrypt later"). The certificate's signature is still classical (RSA or ECDSA): post-quantum
  certificates are not yet issued by public CAs or accepted by browsers.
- Visitors whose software has no post-quantum support (older browsers, many scripts and libraries)
  still connect, classically. The counters show how many.
- One instance, no clustering, no caching, no WAF, no rate limiting. Automatic certificates need
  each name listed (no wildcards) and ports 80 or 443 reachable from the internet.
- It only speaks HTTP(S). Mail, SSH, databases and other protocols are out of scope.

## Privacy

No telemetry. Shield never phones home. The only connections it makes are to `SHIELD_UPSTREAM` and,
for automatic certificates, to the ACME certificate authority. Logs never contain visitor addresses.

## Build and test

```sh
cd shield
go test ./...
docker build -t morrow-shield .
sh ci-smoke.sh morrow-shield      # end to end: docker run, shield check, the page, the redirect
```

Images are published to `ghcr.io/soqlab/morrow-shield` by `.github/workflows/shield.yml` when a
maintainer pushes a `shield-vX.Y.Z` tag.

## License

GNU Affero General Public License v3.0, the same as the rest of this repository
([LICENSE](../LICENSE)).
