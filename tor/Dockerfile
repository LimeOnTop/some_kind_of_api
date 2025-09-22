FROM alpine:3.19

RUN apk add --no-cache tor bash

# Создаём директорию и назначаем владельцем юзера tor
RUN mkdir -p /var/lib/tor/hidden_service && \
    chmod 700 /var/lib/tor/hidden_service && \
    chown -R tor /var/lib/tor

COPY torrc /etc/tor/torrc

USER tor

CMD ["tor", "-f", "/etc/tor/torrc"]
