#!/usr/bin/env python
"""Run the public post-quantum readiness check from a terminal.

The same check as the web page at /check, through the same code
(backend/services/public_check.py), so the capability is not locked behind the
page. Every guardrail still applies: the opt-out list, the SSRF guard, the
per-domain rate limit, the bounded queue, the deadline, the cache and the log.
They are not a web-only courtesy.

    python scripts/pqc-check.py example.com
    python scripts/pqc-check.py example.com --json
    python scripts/pqc-check.py example.com --fresh          # ignore the cache
    python scripts/pqc-check.py example.com --cbom > cbom.json
    python scripts/pqc-check.py --opt-out example.com        # never check it again
    python scripts/pqc-check.py --list-opt-outs
    python scripts/pqc-check.py --settings                  # the guardrails here

Exit status
    0  the endpoint was reached and a verdict was produced
    1  the check ran but reached nothing (a failure, which is not a clean result)
    2  the target was refused: not a hostname, not public, or opted out
    3  rate limited, queued out, or the checker is switched off
    4  something went wrong on this side

It contacts the hostname you name and nothing else, on port 443, at most twice.
Run it against hosts you own, or hosts whose public configuration you have a
legitimate reason to read. If you self-host this service, what it contacts is
your responsibility, under your own jurisdiction's rules.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

BACKEND = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

# The check needs no language model, and a self-hoster running one command should not have to
# configure one. Set before the backend packages are imported.
os.environ.setdefault("PQC_LLM_DISABLED", "1")


def _bold(text: str) -> str:
    return text if os.getenv("NO_COLOR") else f"\033[1m{text}\033[0m"


def _rule(width: int = 72) -> str:
    return "-" * width


def _print_verdict(result: dict) -> None:
    verdict = result.get("verdict") or {}
    observed = result.get("observed") or {}
    certificate = observed.get("certificate") or {}
    ct = result.get("certificate_transparency") or {}
    cache = result.get("cache") or {}

    print()
    print(_bold(f"{result.get('domain')}  -  {verdict.get('headline', '')}"))
    print(_rule())
    print(verdict.get("explanation", ""))
    print()

    print(_bold("Measured in the handshake"))
    rows = [
        ("Address checked", observed.get("address_checked") or "-"),
        ("Port", observed.get("port")),
        ("Connections made", observed.get("connections_made")),
        ("TLS protocol", observed.get("tls_version") or "not observed"),
        ("Cipher suite", observed.get("cipher_name") or "not observed"),
        ("Key exchange", observed.get("key_exchange") if observed.get("key_exchange_observed")
            else f"not observed ({observed.get('key_exchange_unobservable_reason') or 'no reason given'})"),
        ("Key-exchange family", observed.get("key_exchange_family") or "-"),
        ("Certificate key", f"{certificate.get('key_type', '')} {certificate.get('key_bits') or ''}".strip()
            or "not observed"),
        ("Signature algorithm", certificate.get("sig_algorithm") or "not observed"),
        ("Issuer", certificate.get("issuer") or "not observed"),
        ("Expires", certificate.get("not_after") or "not observed"),
        ("Verified against public roots", "yes" if observed.get("certificate_verified") else "no"),
    ]
    if not observed.get("reachable"):
        rows.append(("Why no measurement", observed.get("error") or observed.get("scan_status")))
    for label, value in rows:
        print(f"  {label:<32}{value}")
    print()

    print(_bold("Certificate Transparency (passive; the target was not contacted)"))
    if ct.get("status") == "ok":
        print(f"  {'Provider':<32}{ct.get('provider')}")
        print(f"  {'Unexpired certificates logged':<32}{ct.get('certificate_count')}")
        for issuer in (ct.get("issuers") or [])[:5]:
            print(f"  {'Issuer':<32}{issuer.get('issuer')}  ({issuer.get('certificates')})")
        for key in (ct.get("key_history") or [])[:5]:
            detail = f"{key.get('key_type', '')} {key.get('key_bits') or ''}".strip()
            print(f"  {'Logged certificate key':<32}{detail}  issued {key.get('not_before', '')}")
        if not (ct.get("key_history") or []) and ct.get("reason"):
            print(f"  {'Note':<32}{ct.get('reason')}")
    else:
        print(f"  {'Status':<32}{ct.get('status')}")
        print(f"  {'Reason':<32}{ct.get('reason') or 'none given'}")
        print(f"  {'What this does NOT mean':<32}that the domain has no certificates")
    print()

    print(_bold("Algorithms this endpoint depends on"))
    for item in result.get("algorithms") or []:
        name = item.get("observed_as") or item.get("algorithm")
        status = item.get("status", "unknown")
        extra = item.get("migrate_to") or item.get("reason") or ""
        print(f"  {name!s:<32}{status}" + (f"  -> {extra}" if extra else ""))
    if not (result.get("algorithms") or []):
        print("  none could be read from this endpoint")
    print()

    hndl = result.get("harvest_now_decrypt_later") or {}
    print(_bold("Harvest now, decrypt later (modelled, not measured)"))
    probability = hndl.get("break_probability_by_q_day")
    q_day_year = hndl.get("q_day_year_used")
    if probability is None:
        chance = "not modelled (nothing was observed to model)"
    else:
        chance = f"{probability:.0%} by {q_day_year}"
    print(f"  {'Algorithm class':<32}{hndl.get('algorithm_class')}")
    print(f"  {'Risk tier':<32}{hndl.get('risk_tier')}")
    print(f"  {'P(broken) by modelled Q-Day':<32}{chance}")
    print()

    print(_bold("Published deadlines"))
    for row in result.get("deadlines") or []:
        print(f"  {str(row.get('name'))[:40]:<42}plan by {row.get('soft_deadline')}, "
              f"complete by {row.get('hard_deadline')}")
    print()

    print(_bold("What this check does not tell you"))
    for line in result.get("limits") or []:
        print(f"  - {line}")
    print()

    basis = result.get("model_basis") or {}
    print(_bold("Basis"))
    print(f"  {basis.get('summary', '')}")
    print(f"  Model as of {basis.get('as_of', '')}.")
    print()

    if cache.get("hit"):
        print(f"Served from the cache (checked {cache.get('checked_at')}, "
              f"expires {cache.get('expires_at')}). Use --fresh to re-check.")
    else:
        print(f"Checked {result.get('checked_at')} and cached for "
              f"{int((cache.get('ttl_seconds') or 0) / 60)} minutes.")
    print(f"Permanent record on a running server: {result.get('permalink')}")
    print()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="pqc-check",
        description="Free post-quantum readiness check for one public TLS endpoint.",
        epilog="One hostname, port 443, at most two connections, plus a passive Certificate "
               "Transparency lookup. No port scanning, no subdomain discovery, no vulnerability "
               "probing, no crawling.")
    parser.add_argument("domain", nargs="?", help="the hostname to check, for example example.com")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="print the full result as JSON instead of a report")
    parser.add_argument("--cbom", action="store_true",
                        help="print a CycloneDX 1.6 CBOM for the checked endpoint")
    parser.add_argument("--fresh", action="store_true",
                        help="ignore the cached result (still spends the per-domain budget)")
    parser.add_argument("--settings", action="store_true",
                        help="print this deployment's guardrails and exit")
    parser.add_argument("--opt-out", metavar="DOMAIN", dest="opt_out",
                        help="add a domain to the opt-out list and delete its cached result")
    parser.add_argument("--remove-opt-out", metavar="DOMAIN", dest="remove_opt_out",
                        help="remove a domain from the opt-out list")
    parser.add_argument("--list-opt-outs", action="store_true",
                        help="print the opt-out list")
    parser.add_argument("--log", action="store_true",
                        help="print the recent check log (for investigating an abuse report)")
    args = parser.parse_args(argv)

    from services import public_check as check

    try:
        if args.settings:
            print(json.dumps(check.settings_public(), indent=2))
            return 0
        if args.opt_out:
            print(json.dumps(check.add_optout(args.opt_out, reason="added from the command line",
                                              created_by="cli"), indent=2))
            return 0
        if args.remove_opt_out:
            print(json.dumps(check.remove_optout(args.remove_opt_out), indent=2))
            return 0
        if args.list_opt_outs:
            print(json.dumps({"opt_outs": check.list_optouts(),
                              "configured": sorted(check._optout_set())}, indent=2))
            return 0
        if args.log:
            print(json.dumps(check.recent_log(limit=200), indent=2))
            return 0
    except check.PublicCheckError as exc:
        print(f"{exc.detail}", file=sys.stderr)
        return 2

    if not args.domain:
        parser.print_help()
        return 4

    try:
        result = check.run_check(args.domain, client_ip="cli", force=bool(args.fresh))
    except check.PublicCheckError as exc:
        print(f"{exc.outcome}: {exc.detail}", file=sys.stderr)
        if exc.outcome in {"rate_limited", "queue_full", "queue_timeout", "disabled"}:
            return 3
        if exc.outcome == "error":
            return 4
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 4

    if args.cbom:
        print(json.dumps(check.export_cbom(result), indent=2))
    elif args.as_json:
        print(json.dumps(result, indent=2))
    else:
        _print_verdict(result)

    return 0 if (result.get("observed") or {}).get("reachable") else 1


if __name__ == "__main__":
    sys.exit(main())
