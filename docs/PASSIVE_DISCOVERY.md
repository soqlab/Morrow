# Passive TLS discovery from proxy logs

A scan only sees an endpoint when Morrow connects to it. Your proxies already see every
handshake they terminate, including the **key-exchange group** that decides whether recorded
traffic can be decrypted later by a quantum computer. Passive discovery reads those logs from
a log shipper as a continuous feed and adds what it finds to the inventory with source
`passive`.

For each handshake Morrow extracts **host, port, TLS version, cipher suite and key-exchange
group**, and keeps one row per `(host, port, group, cipher)` with first seen, last seen and a
count.

## Supported sources

| Source | Version | Cipher | Group | Host / port |
| --- | --- | --- | --- | --- |
| nginx | `$ssl_protocol` | `$ssl_cipher` | `$ssl_curve` (nginx 1.21.5+; unknown groups logged as hex, e.g. `0x11ec`, which Morrow resolves) | `$ssl_server_name` / `$host`, `$server_port` |
| Envoy | `%DOWNSTREAM_TLS_VERSION%` | `%DOWNSTREAM_TLS_CIPHER%` | `%DOWNSTREAM_TLS_GROUP%` | `%REQUESTED_SERVER_NAME%`, `%DOWNSTREAM_LOCAL_PORT%` |
| HAProxy | `ssl_fc_protocol` (`%sslv`) | `ssl_fc_cipher` (`%sslc`) | `ssl_fc_curve` (HAProxy built with OpenSSL 3.0+) | `ssl_fc_sni`, `%fp` |
| AWS ALB | `ssl_protocol` (field 16) | `ssl_cipher` (field 15) | **not logged by ALB** | `domain_name` (19), port from the request line |
| Zeek `ssl.log` | `version` | `cipher` | `curve` | `server_name` / `id.resp_h`, `id.resp_p` |

**AWS ALB does not record the key-exchange group** in its access logs, so Morrow never
infers one. A TLS 1.2 ALB handshake is still classified as quantum-vulnerable (only TLS 1.3
defines hybrid post-quantum groups), but a TLS 1.3 handshake seen only through ALB stays
`unknown` until another source or a scan observes the group.

HAProxy: confirm your build names hybrid groups. If `ssl_fc_curve` comes back empty for a
hybrid handshake the group is recorded as "not logged", never as classical.

## Classification

Morrow uses the scanner's own rules (`scanner.classify_key_exchange_group`,
`scanner._is_weak_cipher`), so a passively observed group and a scanned one get the same verdict:

| Observation | `pq_status` | HNDL risk |
| --- | --- | --- |
| Hybrid or pure ML-KEM group (`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`, ...) | `pq_safe_key_exchange` | low |
| Classical group (`x25519`, `secp256r1`, `ffdhe2048`, ...) | `quantum_vulnerable` | high |
| TLS 1.2 or older, whatever the group | `quantum_vulnerable` | high |
| TLS 1.3, group not logged or unregistered code point | `unknown` | unknown |

Legacy TLS (below 1.2) or a weak cipher raises HNDL risk to `critical`. Passive logs never show
the certificate, so the identity half (certificate key) still needs a scan, and every passive
row carries `certificate_observed: false`.

If a host:port shows more than one group (some clients hybrid, some classical), the inventory
asset takes the worst one: a client that can still negotiate classical key exchange can still be
harvested.

## Set up

1. **Create an ingest token** (admin): `POST /v1/runtime/passive/tokens` with
   `{"name": "edge fluent-bit", "default_format": "nginx"}`. The response contains `secret`
   (`mpi_...`) **once**; Morrow stores only a salted HMAC of it. Revoke with
   `DELETE /v1/runtime/passive/tokens/{id}`; revocation applies to the next request.
2. **Log the TLS fields** at the proxy (below).
3. **Point a shipper at** `POST /v1/runtime/passive/ingest?format=<nginx|envoy|haproxy|alb|zeek>`
   with `Authorization: Bearer mpi_...`. `format` can be omitted if the token has a default.
   The organization comes from the token; `x-org-id` is ignored.

Read results with `GET /v1/runtime/passive/endpoints`, or in the console under
**Asset Inventory → Passive discovery**. Inventory rows found this way carry a `passive` badge,
the `passive-discovered` tag and `metadata.discovery_sources: ["passive"]`.

### Proxy log formats

nginx (only server-side fields; no `$remote_addr`, no `$request`):

```nginx
log_format morrow_tls escape=json
  '{"ssl_server_name":"$ssl_server_name","server_port":"$server_port",'
  '"ssl_protocol":"$ssl_protocol","ssl_cipher":"$ssl_cipher","ssl_curve":"$ssl_curve"}';
access_log /var/log/nginx/morrow_tls.log morrow_tls if=$https;
```

Envoy (`typed_config` of a file access log):

```yaml
log_format:
  json_format:
    requested_server_name: "%REQUESTED_SERVER_NAME%"
    downstream_local_port: "%DOWNSTREAM_LOCAL_PORT%"
    downstream_tls_version: "%DOWNSTREAM_TLS_VERSION%"
    downstream_tls_cipher: "%DOWNSTREAM_TLS_CIPHER%"
    downstream_tls_group: "%DOWNSTREAM_TLS_GROUP%"
```

HAProxy (frontend):

```haproxy
log-format "sni=%[ssl_fc_sni] fp=%fp sslv=%sslv sslc=%sslc curve=%[ssl_fc_curve]"
```

AWS ALB: ship the access log files from S3 unchanged (`format=alb`). Zeek: ship `ssl.log`
as JSON (`LogAscii::use_json=T`), or TSV with its `#fields` header in each batch.

### Fluent Bit

```ini
[INPUT]
    Name   tail
    Path   /var/log/nginx/morrow_tls.log
    Tag    morrow.tls

[OUTPUT]
    Name        http
    Match       morrow.tls
    Host        morrow.example.com
    Port        443
    URI         /v1/runtime/passive/ingest?format=nginx
    Format      json_lines
    Header      Authorization Bearer ${MORROW_INGEST_TOKEN}
    Compress    gzip
    tls         On
    tls.verify  On
```

Fluent Bit puts a tailed line under `log`; Morrow unwraps it.

### Vector

```toml
[sources.nginx_tls]
type = "file"
include = ["/var/log/nginx/morrow_tls.log"]

[sinks.morrow]
type = "http"
inputs = ["nginx_tls"]
uri = "https://morrow.example.com/v1/runtime/passive/ingest?format=nginx"
method = "post"
compression = "gzip"
encoding.codec = "json"
framing.method = "newline_delimited"
auth.strategy = "bearer"
auth.token = "${MORROW_INGEST_TOKEN}"
batch.max_bytes = 1000000
batch.timeout_secs = 10
request.rate_limit_num = 60
```

Vector puts the line under `message`; Morrow unwraps it. Filebeat has no HTTP output: send
through Logstash's `http` output (`format => "json_batch"`) with the same URL and header.

## Payloads and limits

Accepted bodies: a JSON array, a JSON object with `lines`/`records`/`logs`, NDJSON, or plain
text (one log line per line), optionally `Content-Encoding: gzip` or `deflate`.

| Limit | Default | Setting |
| --- | --- | --- |
| Body on the wire | 2 MiB | `MORROW_PASSIVE_MAX_BODY_BYTES` |
| Body after decompression | 8 MiB | `MORROW_PASSIVE_MAX_DECODED_BYTES` |
| Lines per batch | 5000 | `MORROW_PASSIVE_MAX_LINES` |
| Requests per token per minute | 120 | `MORROW_PASSIVE_RATE_PER_MINUTE` (Redis-shared when configured) |
| Line length | 16 KiB | fixed; longer lines are counted as `line_too_long` |

Over-limit batches get `413`, over-rate requests `429` with `Retry-After`. A line that cannot be
parsed is **counted, never guessed**: the response reports `unparseable`, a count per reason
(`no_tls_fields`, `missing_host`, `unrecognised_tls_version`, `zeek_tsv_without_fields_header`,
...) and up to 20 samples as `{index, reason}`, never the line itself. Plain-HTTP ALB requests are
`skipped`, not errors.

## Privacy

Morrow stores only server-side facts: host (SNI, Host header or server address), port, TLS
version, cipher, group, the source format, and first/last seen and a count.

* **Never stored:** client IP addresses and ports, request URLs, paths, query strings, user
  agents, headers, cookies, or the raw log line. The parsers never return them, so they cannot
  reach the database; the request line in an ALB entry is read only for the port.
* Unparseable lines are not kept or echoed; only their position and a reason code are.
* Timestamps are Morrow's receive time, not the client's request time.
* Better still, don't send client data at all: the formats above log only server-side fields.
  Logs from Zeek or ALB that do contain client addresses are parsed and dropped line by line.
