"""Atheris (libFuzzer) entry points: coverage-guided, byte-level fuzzing of the same checks the
Hypothesis tests run. Used by .github/workflows/fuzz.yml; needs `pip install atheris` (Linux).

    cd backend
    python -m fuzz.atheris_targets <target> -max_total_time=600 -timeout=10 -rss_limit_mb=1024 \
        work/<target> fuzz/corpus/<target>

<target> is a key of TARGETS. libFuzzer writes new interesting inputs into the first corpus
directory and a crashing input to ./crash-<sha1> (see -artifact_prefix). Minimize one with
-minimize_crash=1 -runs=10000 <file>, then add it to fuzz/corpus/<target>/regressions/.
TARGETS is importable without atheris: test_fuzz_regressions.py replays regression files
through it.
"""

from __future__ import annotations

import sys
from typing import Callable, Dict

from fuzz import checks


def _tls_flight_small_records(data: bytes) -> None:
    checks.check_tls_first_flight(data, chunk=7)


def _json_value(data: bytes) -> None:
    """cert_inventory field parsers: the input is a JSON value as a vendor API would return."""
    import json

    try:
        value = json.loads(data)
    except (ValueError, RecursionError):
        value = data.decode("utf-8", "replace")
    checks.check_cert_inventory_value(value)


TARGETS: Dict[str, Callable[[bytes], None]] = {
    "tls_server_hello": checks.check_tls_server_hello,
    "tls_flight": checks.check_tls_probe,
    "tls_flight_small_records": _tls_flight_small_records,
    "x509": checks.check_x509_der,
    "ike": checks.check_ike_sa_init,
    "ikev1": checks.check_ikev1,
    "ssh": checks.check_ssh_server,
    "ssh_kexinit": checks.check_ssh_kexinit,
    "passive": checks.check_passive_bytes,
    "sbom": checks.check_sbom,
    "cbom": checks.check_cbom,
    "cbom_ingest": checks.check_cbom_ingest,
    "cert_inventory": _json_value,
}

#: Modules whose code Atheris instruments for coverage, per target.
_INSTRUMENT = {
    "tls_server_hello": ["scanner"], "tls_flight": ["scanner"], "tls_flight_small_records": ["scanner"],
    "x509": ["scanner"], "ike": ["ike_scanner"], "ikev1": ["ike_scanner"],
    "ssh": ["ssh_scanner"], "ssh_kexinit": ["ssh_scanner"],
    "passive": ["services.passive_discovery", "services.passive_ingest", "services.json_limits"],
    "sbom": ["services.sbom_import", "services.json_limits"], "cbom": ["services.sbom_import", "services.cbom"],
    "cbom_ingest": ["services.cbom_webhook", "services.json_limits"], "cert_inventory": ["services.cert_inventory"],
}


def main(argv: list) -> None:
    import importlib

    import atheris

    if len(argv) < 2 or argv[1] not in TARGETS:
        sys.exit(f"usage: python -m fuzz.atheris_targets <{'|'.join(TARGETS)}> [libFuzzer args]")
    target = argv.pop(1)
    names = _INSTRUMENT.get(target, [])
    with atheris.instrument_imports(include=names):
        for name in names:
            importlib.import_module(name)
    check = TARGETS[target]

    def one_input(data: bytes) -> None:
        check(data)

    atheris.Setup(argv, one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main(sys.argv)
