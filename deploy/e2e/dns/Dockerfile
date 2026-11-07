# dnsmasq answering the e2e zone, so domain verification reads a real DNS TXT record.
FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
RUN apk add --no-cache dnsmasq
ENTRYPOINT ["dnsmasq", "-k", "--conf-file=/state/dnsmasq.conf"]
