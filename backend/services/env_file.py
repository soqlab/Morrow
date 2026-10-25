"""Environment-file parsing that tolerates a UTF-8 byte order mark, and log redaction for secrets.

Windows editors (Notepad, PowerShell's `Out-File -Encoding utf8`) write a UTF-8 BOM at the start of a
file. python-dotenv keeps it, so `uvicorn --env-file backend/.env` defines "\\ufeffMORROW_VAULT_MASTER_KEY"
instead of MORROW_VAULT_MASTER_KEY: the first variable in the file silently goes missing, and a
naive "NAME=value" error message then echoes the whole line, value included.

Three pieces:

  * parse_env_text / parse_env_file -- a small dotenv-compatible parser (comments, `export`, quotes,
    CRLF) that strips the BOM wherever it appears in front of a name.
  * repair_bom_environ -- for a process already started by a BOM-unaware loader: copies
    "\\ufeffNAME" to NAME when NAME is unset. app.py calls it before reading any setting.
  * redact_secrets -- replaces the values of secret-looking environment variables, URL passwords and
    NAME=value pairs for secret names in a message before it is logged.
"""

from __future__ import annotations

import os
import re
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional

BOM = "﻿"
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
SECRET_NAME_RE = re.compile(
    r"(KEY|SECRET|PASSWORD|PASSWD|PWD|TOKEN|PRIVATE|CREDENTIAL|DSN|DATABASE_URL|BROKER_URL|RESULT_BACKEND|WEBHOOK_URL)",
    re.I,
)
_URL_PASSWORD_RE = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)(?P<user>[^:/@\s]*):(?P<password>[^@/\s]+)@")
_ASSIGNMENT_RE = re.compile(r"(?P<name>﻿?[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;\"']+)")
_MIN_SECRET_LENGTH = 6


def _strip_bom(text: str) -> str:
    return text.lstrip(BOM)


def parse_env_text(text: str) -> Dict[str, str]:
    """Parse dotenv-style text. Later assignments win. Lines that are not assignments are ignored."""
    values: Dict[str, str] = {}
    for raw in _strip_bom(str(text or "")).splitlines():
        line = _strip_bom(raw).strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        name, _, value = line.partition("=")
        name = _strip_bom(name).strip()
        if not _NAME_RE.match(name):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        values[name] = value
    return values


def parse_env_file(path: str) -> Dict[str, str]:
    with open(path, "rb") as handle:
        data = handle.read()
    return parse_env_text(data.decode("utf-8-sig", errors="replace"))


def load_env_file(path: str, override: bool = False, environ: Optional[MutableMapping[str, str]] = None) -> List[str]:
    """Load a file into the environment. Returns the names set (never the values)."""
    target = os.environ if environ is None else environ
    loaded = []
    for name, value in parse_env_file(path).items():
        if override or name not in target:
            target[name] = value
            loaded.append(name)
    return loaded


def repair_bom_environ(environ: Optional[MutableMapping[str, str]] = None) -> List[str]:
    """Rename variables a BOM-unaware loader defined as "\\ufeffNAME". Returns the repaired names."""
    target = os.environ if environ is None else environ
    repaired = []
    for raw_name in [k for k in list(target.keys()) if isinstance(k, str) and k.startswith(BOM)]:
        name = _strip_bom(raw_name)
        if not name:
            continue
        if name not in target:
            target[name] = target[raw_name]
            repaired.append(name)
        try:
            del target[raw_name]
        except KeyError:
            pass
    return repaired


def _secret_values(environ: Mapping[str, str], extra: Iterable[str] = ()) -> List[tuple]:
    pairs = []
    for name, value in environ.items():
        clean = _strip_bom(str(name))
        if SECRET_NAME_RE.search(clean) and value and len(str(value).strip()) >= _MIN_SECRET_LENGTH:
            pairs.append((clean, str(value).strip()))
    for value in extra:
        if value and len(str(value)) >= _MIN_SECRET_LENGTH:
            pairs.append(("secret", str(value)))
    # Longest first, so a value that contains another is replaced whole.
    pairs.sort(key=lambda p: len(p[1]), reverse=True)
    return pairs


def redact_secrets(message: object, environ: Optional[Mapping[str, str]] = None, extra: Iterable[str] = ()) -> str:
    """Return the message with secret values removed. Safe to call on any object (uses str())."""
    text = str(message if message is not None else "")
    env = os.environ if environ is None else environ
    for name, value in _secret_values(env, extra):
        if value in text:
            text = text.replace(value, f"[REDACTED:{name}]")
    text = _URL_PASSWORD_RE.sub(lambda m: f"{m.group('scheme')}{m.group('user')}:[REDACTED]@", text)

    def _assignment(match: "re.Match[str]") -> str:
        name = match.group("name")
        if SECRET_NAME_RE.search(_strip_bom(name)) and not match.group("value").startswith("[REDACTED"):
            return f"{_strip_bom(name)}=[REDACTED]"
        return match.group(0)

    return _ASSIGNMENT_RE.sub(_assignment, text)
