#!/bin/sh
# Steady client traffic for the e2e stack. The mode is read from /state/traffic_mode each round:
#   normal  modern clients (curl with OpenSSL 3.5: X25519MLKEM768 offered) on both Envoy sides
#           and nginx
#   fail    as normal, plus "old" clients offering only X25519 against the PQ-only Envoy listener
#           (handshake failures) and requests to /fail there (HTTP 503s)
apk add --no-cache curl >/dev/null 2>&1 || true
C="--cacert /certs/ca.pem -s -o /dev/null --max-time 3"
while true; do
  # A prefix match, so a trailing carriage return from a Windows editor does not matter.
  case "$(cat /state/traffic_mode 2>/dev/null)" in
    fail*) mode=fail ;;
    *) mode=normal ;;
  esac
  for i in 1 2; do
    curl $C https://envoy.e2e.morrow.test:10443/ || true
    curl $C https://envoy.e2e.morrow.test:11443/ || true
    curl $C https://nginx.e2e.morrow.test/ || true
    if [ "$mode" = "fail" ]; then
      curl $C --curves X25519 https://envoy.e2e.morrow.test:11443/ || true
      curl $C https://envoy.e2e.morrow.test:11443/fail || true
    fi
  done
  sleep 2
done
