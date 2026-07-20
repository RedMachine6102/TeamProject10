FROM caddy@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648

RUN addgroup -S -g 10001 vaultproxy && \
    adduser -S -D -H -u 10001 -G vaultproxy vaultproxy && \
    setcap -r /usr/bin/caddy && \
    mkdir -p /data /config && \
    chown -R vaultproxy:vaultproxy /data /config

COPY Caddyfile /etc/caddy/Caddyfile

USER vaultproxy
