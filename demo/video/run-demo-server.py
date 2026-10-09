"""Start an isolated Airlock Command server for demo-video recording.

Runs on port 8049 against a throwaway SQLite database so the real local
server on 8001 and backend/pqc_scanner.db are never touched.

  backend/.venv/Scripts/python.exe demo/video/run-demo-server.py

Environment comes from backend/.env (BOM tolerated, never printed).
OPENAI_API_KEY is deliberately dropped so nothing in the recording can
make a third-party network call.
"""
import os
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
DEMO_DB = pathlib.Path(os.environ.get("PQC_DEMO_DB") or (ROOT / "demo" / "video" / "demo.db"))

env_file = BACKEND / ".env"
if env_file.exists():
    for raw in env_file.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key:
            os.environ[key] = val

# No outbound third-party calls from anything the camera sees.
for k in ("OPENAI_API_KEY", "OPENAI_MODEL", "ANTHROPIC_API_KEY"):
    os.environ.pop(k, None)

os.environ["PQC_SCANNER_DB"] = str(DEMO_DB)
os.environ["PQC_ENVIRONMENT"] = "local"
# Production-shaped auth so the console shows no "spoofable role" advisory on camera.
os.environ["PQC_AUTH_MODE"] = "jwt"
os.environ["PQC_AUTH_REQUIRED"] = "1"
os.environ["PQC_DEFAULT_ROLE"] = "viewer"
os.environ["PQC_ADMIN_EMAIL"] = "avery.chen@example.com"
# Throwaway credential for the throwaway demo database on 127.0.0.1 only.
os.environ["PQC_ADMIN_PASSWORD"] = "Airlock-Demo-Recording-8049"
os.environ.setdefault("PQC_DISABLE_SCHEDULER", "1")

DEMO_DB.parent.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(BACKEND))
os.chdir(BACKEND)

import uvicorn  # noqa: E402

port = int(os.environ.get("PQC_DEMO_PORT", "8049"))
print(f"demo server: db={DEMO_DB} port={port}", flush=True)
uvicorn.run("app:app", host="127.0.0.1", port=port, log_level="warning")
