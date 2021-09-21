
FROM quay.io/oauth2-proxy/oauth2-proxy

RUN apk --no-cache add curl

COPY oauth2-proxy.cfg .

ENTRYPOINT ["/bin/oauth2-proxy", "--config=./oauth2-proxy.cfg"]
