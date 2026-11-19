# Pre-flight: the inside test

Before you switch on post-quantum key exchange (X25519MLKEM768), check that the larger ClientHello
gets through your own network. `preflight.py` is one Python file, standard library only. Copy it to
a machine inside your network and run it against your own hosts. It sends nothing to Morrow or to
anyone else.

Morrow's site runs the same test from the public internet (`/<domain>` and `/r/<domain>`, "Before
you switch: pre-flight", or `GET /api/public/preflight/<domain>`). That covers only the public path to
your public address. This script covers the paths Morrow cannot reach: internal load balancers,
TLS-inspecting proxies, firewalls between network zones, VPNs, and hosts on private addresses.

## Why the size matters

The X25519MLKEM768 key share is 1,216 bytes, against 32 bytes for X25519. A Chromium 140 ClientHello
measured 1,756 bytes with it (about 540 without the 1,220 bytes of the hybrid share), which no longer fits in one TCP segment on an ordinary
1,500-byte path, so it arrives in two. TCP has always allowed that, but some firewalls, load
balancers, TLS-inspecting proxies and TLS servers read only the first segment, or call `read()` once,
and then fail. The client sees a timeout or a reset.

- Chromium blog, [Protecting Chrome Traffic with Hybrid Kyber KEM](https://blog.chromium.org/2023/08/protecting-chrome-traffic-with-hybrid.html) (2023-08-10): over a kilobyte more in the ClientHello, and "TLS middleboxes failed due to improperly hardcoded restrictions on message size".
- [tldr.fail](https://tldr.fail/): the bug, its symptoms, and the products that had it and their fixes. It also describes the test this script runs: send half a ClientHello, pause, send the rest.
- Cloudflare, [Automatic Key Exchange](https://blog.cloudflare.com/automatic-key-exchange-for-origins/) (2026-09-08): about 0.34% of the origins it scanned failed when sent a post-quantum key share first.
- Cloudflare Radar, [post-quantum TLS bug detection](https://developers.cloudflare.com/changelog/post/2026-05-29-radar-pq-tls-bug-detection/) (2026-05-29): the same comparison, a fragmented post-quantum hello against a classical one.

## Run it

```
python3 preflight.py intranet.example.internal
python3 preflight.py 10.0.0.12:8443 --sni app.example.internal
python3 preflight.py host-a host-b:8443 --json > preflight.json
python3 preflight.py --file hosts.txt --timeout 8
```

Python 3.8 or newer. Targets are `host`, `host:port`, `[ipv6]:port` or `https://host:port`. With
`--file`, one target per line; `#` starts a comment.

| Option | Default | |
|---|---|---|
| `--port N` | 443 | port for targets that name none |
| `--sni NAME` | the host | server name to send when the target is an address |
| `--timeout S` | 6 | seconds to wait for each answer |
| `--no-split` | off | skip the hello sent in two parts |
| `--json` | off | one JSON document, the same fields as Morrow's API (`api_version` `preflight/1`) |

Exit status: 0 when every host is safe or already quantum-safe, 1 when any host has a path problem,
2 when any host could not be tested, 64 for bad arguments. So it also works as a CI or change gate.

## What it sends

For each host, three TLS ClientHellos, each on its own TCP connection. Each connection is closed as
soon as the server's first answer arrives. No handshake is completed and no HTTP request is made.

| Hello | Groups offered | Size | Sent as |
|---|---|---|---|
| Classical | X25519, P-256, P-384; one X25519 key share | about 250 bytes | one write, one segment |
| Post-quantum | X25519MLKEM768 first, then the classical groups; X25519MLKEM768 and X25519 key shares | 1,756 bytes, the size of a Chromium 140 ClientHello (padded with the RFC 7685 padding extension) | one write; the operating system splits it |
| Post-quantum, in two parts | the same | 1,756 bytes | two writes 200 ms apart with Nagle off, so the halves arrive as separate reads |

If the classical hello gets an answer and a post-quantum one does not, the failing hello and the
classical one are each sent once more. "Path problem" means the failure happened twice.

The key shares are real X25519 public keys (computed in the script, RFC 7748) and a well-formed
ML-KEM-768 encapsulation key. The script never decapsulates, because it never finishes the handshake.

## The verdicts

| Verdict | Means |
|---|---|
| **Safe to turn on.** | The post-quantum hellos got answers, as the classical one did. Nothing on this path blocks them. |
| **Path problem.** | The classical hello got an answer and a post-quantum one failed (timed out, was reset, or got a TLS alert), twice. Something on the path mishandles a ClientHello in more than one TCP segment. |
| **Server already quantum-safe.** | The server chose X25519MLKEM768. |
| **Couldn't test.** | Nothing accepted a connection, or not even the classical hello got an answer. |

For a path problem, the documented fixes are:

1. Update the firewall, load balancer or proxy on the path to a release that fixes it. tldr.fail
   lists vendors that have shipped fixes (Palo Alto, Zscaler, Broadcom ProxySG, Apache Traffic
   Server and others) and the open Cisco bug CSCwj82736.
2. Turn on the vendor's fix for a split ClientHello if it has one (Envoy's is configuration only).
   Look for a setting to buffer or reassemble the whole ClientHello before inspecting it.
3. If nothing sits in between, look at the server's own TLS code: a server that expects the whole
   ClientHello from one `read()` has the same bug.

Browsers already send this larger hello (Chrome and Firefox offer X25519MLKEM768 by default). A
path problem can therefore already be failing some of your users' connections, whether or not you
switch anything on.

## What it does not cover

- Only the path from the machine you run it on to each host. Run it from each network zone that matters.
- Only TCP. QUIC (HTTP/3) never assumed a one-packet ClientHello, so this problem is much rarer there.
- Post-quantum (ML-DSA) certificates are not in the web PKI yet, so nothing here tests them. They
  will make the server's answer larger too; testing that is future work.

AGPL-3.0, part of [Morrow](https://github.com/soqlab/Morrow). Morrow is not affiliated with any vendor named here.
