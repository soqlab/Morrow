"""Print the MORROW_PLATFORM_OPERATORS value for an admin passphrase of your choosing.

Run it on your own computer:  python scripts/set-admin-passphrase.py
It asks for the passphrase twice (nothing is shown or stored) and prints one line. Paste that line
as the value of MORROW_PLATFORM_OPERATORS in the hosting dashboard. Then sign in to /vendor-admin
with the passphrase in the "operator key" field, plus your authenticator code.

The operator name stays "owner", so an authenticator already enrolled for it keeps working.
"""

import getpass
import hashlib
import json
import sys

MIN_LENGTH = 14


def main() -> int:
    passphrase = getpass.getpass(f"New admin passphrase (at least {MIN_LENGTH} characters): ")
    if len(passphrase) < MIN_LENGTH:
        print(f"Too short: use at least {MIN_LENGTH} characters, for example four random words.")
        return 1
    if passphrase != passphrase.strip():
        print("Leave out spaces at the start and end.")
        return 1
    if getpass.getpass("Type it again: ") != passphrase:
        print("The two entries did not match. Nothing was changed.")
        return 1
    entry = [{"name": "owner", "role": "owner", "key_sha256": hashlib.sha256(passphrase.encode("utf-8")).hexdigest()}]
    print("\nPaste this as the value of MORROW_PLATFORM_OPERATORS:\n")
    print(json.dumps(entry))
    return 0


if __name__ == "__main__":
    sys.exit(main())
