ARG GO_VER=1.16.9
ARG ALPINE_VER=3.13

FROM alpine:${ALPINE_VER} as copa-tokens-base
RUN apk add --no-cache tzdata
RUN echo 'hosts: files dns' > /etc/nsswitch.conf
RUN mkdir -p /etc/copa-europe-tokens/config
RUN mkdir -p /etc/copa-europe-tokens/crypto

FROM golang:${GO_VER}-alpine${ALPINE_VER} as golang
RUN apk add --no-cache \
    bash \
    binutils-gold \
    gcc \
    git \
    make \
    musl-dev
ADD . $GOPATH/src/github.com/copa-europe-tokens
WORKDIR $GOPATH/src/github.com/copa-europe-tokens

FROM golang as copa-tokens-server
RUN make binary

FROM copa-tokens-base
VOLUME /etc/copa-europe-tokens/config
VOLUME /etc/copa-europe-tokens/crypto
COPY --from=copa-tokens-server /go/src/github.com/copa-europe-tokens/bin/copaTokens /usr/local/bin
COPY --from=copa-tokens-server /go/src/github.com/copa-europe-tokens/deployment/config-docker /etc/copa-europe-tokens/config
EXPOSE 6101
CMD ["copaTokens", "start", "--configpath", "/etc/copa-europe-tokens/config/."]
