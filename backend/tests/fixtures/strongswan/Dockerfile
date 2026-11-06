# strongSwan responder used to test ike_scanner.py against a real IKEv2 implementation.
# Alpine edge ships strongSwan 6.x with OpenSSL 3.5+, which provides ML-KEM (IKEv2 KE 35-37).
FROM alpine:edge
RUN apk add --no-cache strongswan openssl
COPY swanctl.conf /etc/swanctl/swanctl.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 500/udp 4500/udp
ENTRYPOINT ["/entrypoint.sh"]
