
FROM quay.io/oauth2-proxy / oauth2-proxy

COPY oauth2-proxy.cfg .

USER 2000:2000

ENTRYPOINT ["/bin/oauth2-proxy", "--config=./oauth2-proxy.cfg"]
