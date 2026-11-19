#!/bin/sh
# End-to-end check of a built Shield image, as a user would run it:
#   sh ci-smoke.sh morrow-shield:ci
# A plain-HTTP "old app" on the host, Shield in front of it (read-only filesystem, no capabilities,
# non-root), then: the key exchange a browser gets, a classical client, the proxied page, the
# HTTP redirect, and automatic-certificate mode starting on a fresh volume. Needs docker, openssl,
# python3 and curl.
set -eu
IMAGE=${1:?usage: ci-smoke.sh IMAGE}
HOST=shop.example.test
WORK=$(mktemp -d)
cleanup() {
  docker rm -f shield-smoke shield-smoke-acme >/dev/null 2>&1 || true
  docker volume rm shield-smoke-data >/dev/null 2>&1 || true
  [ -n "${APP:-}" ] && kill "$APP" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== the old app: plain HTTP on the host, port 18081"
mkdir -p "$WORK/app" "$WORK/certs"
echo "hello from the old app" > "$WORK/app/index.html"
python3 -m http.server 18081 --bind 0.0.0.0 --directory "$WORK/app" >/dev/null 2>&1 &
APP=$!

echo "== a test certificate for $HOST"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj "/CN=$HOST" \
  -addext "subjectAltName=DNS:$HOST" -keyout "$WORK/certs/key.pem" -out "$WORK/certs/cert.pem" 2>/dev/null
chmod 644 "$WORK/certs/key.pem"   # readable by the image's user (65532)

test "$(docker inspect --format '{{.Config.User}}' "$IMAGE")" = "65532:65532"

echo "== docker run"
docker run -d --name shield-smoke --read-only --cap-drop ALL --security-opt no-new-privileges \
  --add-host host.docker.internal:host-gateway -p 127.0.0.1:18443:8443 -p 127.0.0.1:18080:8080 \
  -v "$WORK/certs:/certs:ro" -e SHIELD_DOMAINS=$HOST -e SHIELD_UPSTREAM=http://host.docker.internal:18081 \
  -e SHIELD_CERT=/certs/cert.pem -e SHIELD_KEY=/certs/key.pem -e SHIELD_LOG_CONNECTIONS=1 "$IMAGE" >/dev/null
for i in $(seq 1 30); do docker exec shield-smoke /usr/local/bin/shield health 2>/dev/null && break; sleep 1; done
docker exec shield-smoke /usr/local/bin/shield health

echo "== shield check (as a current browser)"
docker exec shield-smoke /usr/local/bin/shield check -insecure -servername $HOST 127.0.0.1:8443 | tee "$WORK/check.txt"
grep -q "key exchange   X25519MLKEM768 (hybrid post-quantum)" "$WORK/check.txt"

echo "== shield check -classical (as an old client)"
set +e; docker exec shield-smoke /usr/local/bin/shield check -insecure -classical -servername $HOST 127.0.0.1:8443; code=$?; set -e
test "$code" = 2

echo "== the page through Shield"
curl -fsS --cacert "$WORK/certs/cert.pem" --resolve $HOST:18443:127.0.0.1 https://$HOST:18443/ | tee "$WORK/page.txt"
grep -q "hello from the old app" "$WORK/page.txt"

echo "== http:// redirects to https://"
out=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H "Host: $HOST" http://127.0.0.1:18080/basket?x=1)
echo "$out"
test "$out" = "301 https://$HOST/basket?x=1"

echo "== the counters Shield logs"
docker kill --signal TERM shield-smoke >/dev/null
sleep 2
docker logs shield-smoke 2>&1 | tee "$WORK/log.txt"
grep -q 'msg="key exchange" connections=' "$WORK/log.txt"
grep -q "group=X25519MLKEM768" "$WORK/log.txt"

echo "== automatic certificates: starts on a fresh named volume, read-only root"
docker run -d --name shield-smoke-acme --read-only --cap-drop ALL -v shield-smoke-data:/data \
  -e SHIELD_DOMAINS=$HOST -e SHIELD_UPSTREAM=http://127.0.0.1:1 -e SHIELD_ACME_URL=https://127.0.0.1:1/directory \
  "$IMAGE" >/dev/null
for i in $(seq 1 30); do docker exec shield-smoke-acme /usr/local/bin/shield health 2>/dev/null && break; sleep 1; done
docker exec shield-smoke-acme /usr/local/bin/shield health
echo "smoke: all good"
