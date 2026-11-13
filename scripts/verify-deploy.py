#!/usr/bin/env python3
"""Check that a running Morrow server serves exactly the pages of a public commit.

What it checks, against a server you name and a local git checkout of the Morrow repository:

  1. /api/public/build reports a commit (servers that do not know their commit fail here).
  2. /api/public/manifest names the same commit, and every file it lists under /ui/ has the
     SHA-256 and size of ``git show <commit>:backend/static/<file>`` in your checkout. Files in
     the commit that the manifest does not list are reported too.
  3. /api/public/deploys: every entry_hash is recomputed and the chain is checked link by link,
     from 64 zeros when the whole log is returned; the newest entry should be the running commit.

Dependencies: the Python standard library and git. Run ``git fetch`` first so the commit exists in your checkout.

Usage:
    python scripts/verify-deploy.py --url https://morrow.soqlab.com --repo .

Exit status: 0 everything matched, 1 a check failed, 2 the server or the checkout could not be read.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import urllib.request
from typing import Any, Callable, Dict, List, Optional

MANIFEST_FORMAT = "morrow.page-files/v1"
GENESIS_HASH = "0" * 64
URL_PREFIX = "/ui/"
STATIC_IN_REPO = "backend/static/"


class ReadError(Exception):
    """The server or the checkout could not be read (exit 2)."""


def canonical_bytes(value: Any) -> bytes:
    """Sorted keys, no whitespace, UTF-8: the bytes Morrow hashes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


# ── pure checks ──────────────────────────────────────────────────────────────


def check_files(files: List[Dict[str, Any]], read_blob: Callable[[str], Optional[bytes]],
                repo_names: Optional[List[str]] = None) -> List[str]:
    """Problems with the manifest's file list. read_blob(name) returns the committed bytes or None."""
    problems: List[str] = []
    listed = set()
    for item in files:
        path = str(item.get("path") or "")
        if not path.startswith(URL_PREFIX) or ".." in path.split("/"):
            problems.append(f"{path}: not a /ui/ path")
            continue
        name = path[len(URL_PREFIX):]
        listed.add(name)
        blob = read_blob(name)
        if blob is None:
            problems.append(f"{path}: served, but not in the commit")
            continue
        digest = hashlib.sha256(blob).hexdigest()
        if digest != item.get("sha256"):
            problems.append(f"{path}: sha256 {item.get('sha256')} served, {digest} in the commit")
        elif int(item.get("bytes", -1)) != len(blob):
            problems.append(f"{path}: {item.get('bytes')} bytes served, {len(blob)} in the commit")
    for name in repo_names or []:
        if name not in listed and not any(part.startswith(".") for part in name.split("/")):
            problems.append(f"{URL_PREFIX}{name}: in the commit, missing from the manifest")
    return problems


def entry_hash(entry: Dict[str, Any]) -> str:
    body = {"seq": int(entry["seq"]), "commit": str(entry["commit"]), "first_seen": str(entry["first_seen"]),
            "prev_hash": str(entry["prev_hash"])}
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def check_chain(entries_newest_first: List[Dict[str, Any]], count: int, head_hash: Optional[str]) -> List[str]:
    """Recompute every hash and link. From genesis when the whole log is present."""
    problems: List[str] = []
    entries = list(reversed(entries_newest_first))
    complete = len(entries) == int(count)
    prev: Optional[str] = GENESIS_HASH if complete else None
    expected_seq: Optional[int] = 1 if complete else None
    for e in entries:
        try:
            seq = int(e["seq"])
            if expected_seq is not None and seq != expected_seq:
                problems.append(f"entry {seq}: expected seq {expected_seq}")
            if prev is not None and e["prev_hash"] != prev:
                problems.append(f"entry {seq}: prev_hash does not match the previous entry")
            if entry_hash(e) != e["entry_hash"]:
                problems.append(f"entry {seq}: entry_hash does not match its contents")
            prev, expected_seq = e["entry_hash"], seq + 1
        except (KeyError, TypeError, ValueError):
            problems.append("an entry is malformed")
            return problems
    if entries and head_hash != entries[-1]["entry_hash"]:
        problems.append("head_hash is not the newest entry's hash")
    if not entries and head_hash:
        problems.append("head_hash given for an empty log")
    return problems


# ── I/O ──────────────────────────────────────────────────────────────────────


def fetch_json(url: str, timeout: float = 20.0) -> Dict[str, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/json",
                                                   "User-Agent": "morrow-verify-deploy/1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310  # https URL given by the user
            return json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise ReadError(f"could not read {url}: {exc}") from exc


def git_blob_reader(repo: str, commit: str) -> Callable[[str], Optional[bytes]]:
    def read(name: str) -> Optional[bytes]:
        done = subprocess.run(["git", "-C", repo, "show", f"{commit}:{STATIC_IN_REPO}{name}"],
                              capture_output=True, check=False)
        return done.stdout if done.returncode == 0 else None

    return read


def git_static_names(repo: str, commit: str) -> List[str]:
    done = subprocess.run(["git", "-C", repo, "ls-tree", "-r", "--name-only", commit, STATIC_IN_REPO],
                          capture_output=True, check=False)
    if done.returncode != 0:
        raise ReadError(f"commit {commit} is not in {repo} (git fetch first?): "
                        + done.stderr.decode("utf-8", "replace").strip())
    return [line[len(STATIC_IN_REPO):] for line in done.stdout.decode("utf-8").splitlines()
            if line.startswith(STATIC_IN_REPO)]


def run(url: str, repo: str, out=sys.stdout) -> int:
    base = url.rstrip("/")
    build = fetch_json(base + "/api/public/build")
    commit = build.get("commit")
    problems: List[str] = []
    if not commit:
        out.write("FAIL the server does not report its commit\n")
        return 1
    out.write(f"server runs {commit}\n")
    manifest = fetch_json(base + "/api/public/manifest")
    if manifest.get("format") != MANIFEST_FORMAT:
        problems.append("the manifest has an unexpected format")
    if manifest.get("commit") != commit:
        problems.append(f"the manifest names commit {manifest.get('commit')}, the build endpoint {commit}")
    names = git_static_names(repo, commit)
    file_problems = check_files(manifest.get("files") or [], git_blob_reader(repo, commit), names)
    problems += file_problems
    out.write(f"{len(manifest.get('files') or [])} files checked against {commit[:12]}: "
              f"{'ok' if not file_problems else str(len(file_problems)) + ' problems'}\n")
    deploys = fetch_json(base + "/api/public/deploys?limit=500")
    entries = deploys.get("entries") or []
    chain_problems = check_chain(entries, int(deploys.get("count") or 0), deploys.get("head_hash"))
    if deploys.get("chain_ok") is not True:
        chain_problems.append("the server reports its own chain as broken")
    if entries and entries[0].get("commit") != commit:
        chain_problems.append("the newest deploy-log entry is not the running commit")
    if not entries:
        chain_problems.append("the deploy log is empty")
    problems += chain_problems
    out.write(f"deploy log: {deploys.get('count')} entries, head {deploys.get('head_hash')}: "
              f"{'ok' if not chain_problems else str(len(chain_problems)) + ' problems'}\n")
    for problem in problems:
        out.write("FAIL " + problem + "\n")
    out.write("verified\n" if not problems else f"{len(problems)} problems\n")
    return 0 if not problems else 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Check a Morrow server's pages against a public commit.")
    parser.add_argument("--url", required=True, help="the server, e.g. https://morrow.soqlab.com")
    parser.add_argument("--repo", default=".", help="a local git checkout of the Morrow repository")
    args = parser.parse_args(argv)
    try:
        return run(args.url, args.repo)
    except ReadError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
