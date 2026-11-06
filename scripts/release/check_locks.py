"""Check that the hashed lock files still agree with the hand-edited requirement files.

    python -I scripts/release/check_locks.py

Every exact pin (name==version) in a requirements .txt must appear with the same version in its
lock, and every lock entry must carry at least one --hash. Fails with a message naming
scripts/release/lock-requirements.sh when someone edits a .txt and forgets to relock.
Standard library only; run by the release workflow before anything is built.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAIRS = {
    "backend/requirements.lock": ["backend/requirements.txt"],
    "backend/requirements-dev.lock": ["backend/requirements.txt", "backend/requirements-dev.txt"],
    "backend/requirements-bootstrap.lock": ["backend/requirements-bootstrap.txt"],
    "scripts/release/sbom-tools.lock": ["scripts/release/sbom-tools.txt"],
}
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?==([^\s;#\\]+)")


def canon(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def pins(text):
    out = {}
    for line in text.splitlines():
        m = PIN.match(line.strip())
        if m:
            out[canon(m.group(1))] = m.group(3)
    return out


def lock_entries(text):
    """name -> (version, has_hash), joining backslash-continued lines."""
    out = {}
    joined = re.sub(r"\\\s*\n", " ", text)
    for line in joined.splitlines():
        m = PIN.match(line.strip())
        if m:
            out[canon(m.group(1))] = (m.group(3), "--hash=sha256:" in line)
    return out


def main():
    problems = []
    for lock, sources in PAIRS.items():
        lock_path = ROOT / lock
        if not lock_path.exists():
            problems.append(f"{lock} is missing")
            continue
        entries = lock_entries(lock_path.read_text(encoding="utf-8"))
        for name, (version, hashed) in sorted(entries.items()):
            if not hashed:
                problems.append(f"{lock}: {name}=={version} has no --hash")
        for source in sources:
            for name, version in sorted(pins((ROOT / source).read_text(encoding="utf-8")).items()):
                got = entries.get(name, (None,))[0]
                if got != version:
                    problems.append(f"{source} pins {name}=={version} but {lock} has {got or 'nothing'}")
    if problems:
        print("\n".join(problems))
        print("\nRun: sh scripts/release/lock-requirements.sh")
        sys.exit(1)
    print(f"{len(PAIRS)} lock files agree with their requirement files")


if __name__ == "__main__":
    main()
