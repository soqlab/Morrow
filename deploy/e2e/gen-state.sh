#!/bin/sh
# Generate the throw-away state the e2e stack needs: a private CA, TLS certificates for the
# nginx, Envoy and Prometheus containers, the backend's vault key, and the initial dnsmasq and
# nginx group files. Everything goes to deploy/e2e/state/ (git-ignored). Test-only material:
# never reuse it anywhere else.
#
#   sh deploy/e2e/gen-state.sh          # creates state/ if it does not exist yet
#   sh deploy/e2e/gen-state.sh --force  # regenerates it
set -eu
export MSYS2_ARG_CONV_EXCL="*"   # Git Bash on Windows: keep "/CN=..." as is
HERE=$(cd "$(dirname "$0")" && pwd)
STATE="$HERE/state"
if [ -d "$STATE" ] && [ "${1:-}" != "--force" ]; then
  echo "state/ exists; pass --force to regenerate"
  exit 0
fi
rm -rf "$STATE"
mkdir -p "$STATE/certs" "$STATE/logs"
cd "$STATE/certs"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
  -subj "/CN=Morrow e2e test CA" -keyout ca.key -out ca.pem \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

leaf() {  # leaf <name> <key type args> <san list>
  name=$1; shift; keyargs=$1; shift; san=$1
  # shellcheck disable=SC2086
  openssl req -newkey $keyargs -nodes -subj "/CN=$name" -keyout "$name.key" -out "$name.csr" 2>/dev/null
  printf "subjectAltName=%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" "$san" > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 \
    -extfile "$name.ext" -out "$name.pem" 2>/dev/null
  rm -f "$name.csr" "$name.ext"
}
# nginx serves an RSA-2048 certificate on purpose: the "before" state for the kill switch.
leaf nginx "rsa:2048" "DNS:nginx.e2e.morrow.test"
leaf envoy "ec -pkeyopt ec_paramgen_curve:prime256v1" "DNS:envoy.e2e.morrow.test"
leaf prometheus "ec -pkeyopt ec_paramgen_curve:prime256v1" "DNS:prometheus.e2e.morrow.test"
chmod 644 ./*.key ./*.pem   # read by non-root container users (nginx, envoy, nobody)

# Backend vault key (Fernet key: 32 random bytes, url-safe base64) for sealed secrets and proof keys.
head -c 32 /dev/urandom | base64 | tr "+/" "-_" > "$STATE/vault.key"

# dnsmasq answers only the e2e zone; the TXT record is added once the domain token is known.
cat > "$STATE/dnsmasq.conf" <<'EOF'
local=/e2e.morrow.test/
log-queries
EOF
# nginx starts classical-only (X25519 / P-256): the "before" state.
echo "ssl_ecdh_curve X25519:prime256v1;" > "$STATE/nginx-groups.conf"
echo normal > "$STATE/traffic_mode"
chmod -R a+rwX "$STATE/logs"
echo "state written to $STATE"
