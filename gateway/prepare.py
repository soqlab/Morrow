"""Import a one-time console provisioning bundle into local gateway files."""
import argparse
import json
import os
import re
from pathlib import Path


def prepare(bundle_path, output, rotate=False):
    value = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    if not re.fullmatch(r"[a-f0-9]{64}", value.get("secret", "")):
        raise ValueError("Invalid provisioning secret")
    if not re.fullmatch(r"[a-f0-9]{32}", value.get("policy", {}).get("site_id", "")):
        raise ValueError("Invalid site policy")
    output = Path(output).resolve()
    state = output / "state" / "policy.json"
    secret = output / "secrets" / "gateway.secret"
    if (state.exists() or secret.exists()) and not rotate:
        raise ValueError("Provisioning already exists; use --rotate only for an approved credential rotation")
    for folder in (state.parent, secret.parent, output / "certs"):
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    for path, text in ((state, json.dumps(value["policy"], sort_keys=True, separators=(",", ":"))), (secret, value["secret"])):
        temporary = path.with_suffix(".new")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle")
    parser.add_argument("--output", default=str(Path(__file__).resolve().parent / "local"))
    parser.add_argument("--rotate", action="store_true")
    args = parser.parse_args()
    target = prepare(args.bundle, args.output, args.rotate)
    print(f"Provisioning saved under {target}. Secret contents were not printed.")
    print("Supply certs/fullchain.pem and certs/privkey.pem for the verified public hostname.")
    print("On Linux, set AIRLOCK_GATEWAY_UID/GID to the owner of these files before starting Compose.")
    print("Delete the downloaded bundle securely after storing the credential in your approved secret manager.")
