#!/bin/sh
# First-time setup for Morrow inside a company network. Run once, from this folder.
#   1. loads the images from the bundle (if images.tar.gz is here)
#   2. creates morrow.env with fresh secrets, and .env with the site address
# Then edit morrow.env (address, first administrator) and run: docker compose up -d
set -eu
cd "$(dirname "$0")"

if [ -f images.tar.gz ]; then
  echo "Loading images (this takes a minute)..."
  gunzip -c images.tar.gz | docker load
fi

mkdir -p ca tls

if [ -f morrow.env ]; then
  echo "morrow.env already exists; leaving it as it is."
else
  secret() { head -c "$1" /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'; }
  # The vault key must be a Fernet key: 32 random bytes, URL-safe base64 with padding.
  vault="$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '\n')"
  sed -e "s|^MORROW_AUTH_JWT_SECRET=.*|MORROW_AUTH_JWT_SECRET=$(secret 48)|" \
      -e "s|^MORROW_VAULT_MASTER_KEY=.*|MORROW_VAULT_MASTER_KEY=${vault}|" \
      -e "s|^MORROW_AIRLOCK_SIGNING_KEY=.*|MORROW_AIRLOCK_SIGNING_KEY=$(secret 48)|" \
      morrow.env.example > morrow.env
  chmod 600 morrow.env
  echo "Created morrow.env with new secrets."
  echo "Copy MORROW_VAULT_MASTER_KEY from it into your password manager: without it, a restored"
  echo "backup cannot decrypt stored credentials."
fi

[ -f .env ] || printf 'SITE_ADDRESS=morrow.corp.example\n' > .env

echo
echo "Next:"
echo "  1. Edit .env and morrow.env: your address and the first administrator."
echo "  2. Put the certificate in tls/cert.pem and tls/key.pem (or see Caddyfile)."
echo "  3. Optional: your company CA as ca/company.crt."
echo "  4. docker compose up -d"
