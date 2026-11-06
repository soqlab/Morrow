#!/bin/sh
# Start charon in the foreground and load the swanctl configuration once its VICI socket is up.
set -e
CHARON=$(ls /usr/libexec/ipsec/charon /usr/lib/ipsec/charon /usr/lib/strongswan/charon 2>/dev/null | head -1)
"$CHARON" --debug-ike 2 --debug-cfg 2 &
pid=$!
for i in $(seq 1 50); do
  swanctl --stats >/dev/null 2>&1 && break
  sleep 0.2
done
swanctl --load-all
swanctl --list-conns
wait $pid
