
FROM quay.io/oauth2-proxy/oauth2-proxy

RUN addgroup -S 2000 && adduser -S -G 2000 2000

COPY oauth2-proxy.cfg .

RUN apk --no-cache add curl

USER 2000:2000

ENTRYPOINT ["/bin/oauth2-proxy", "--config=./oauth2-proxy.cfg"]
