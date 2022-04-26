FROM alpine:3.14

RUN apk add --no-cache ca-certificates

# set up nsswitch.conf for Go's "netgo" implementation
# - https://github.com/golang/go/blob/go1.9.1/src/net/conf.go#L194-L275
# - docker run --rm debian:stretch grep '^hosts:' /etc/nsswitch.conf
RUN [ ! -e /etc/nsswitch.conf ] && echo 'hosts: files dns' > /etc/nsswitch.conf

ENV PATH /usr/local/go/bin:$PATH

ENV GOLANG_VERSION 1.17.9

ADD . /usr/local/go

ARG GO_TAGS=

RUN set -eux; \
	arch="$(apk --print-arch)"; \
	case "$arch" in \
		'x86_64') \
			export GOARCH='amd64' GOOS='linux'; \
			;; \
		'armhf') \
			export GOARCH='arm' GOARM='6' GOOS='linux'; \
			;; \
		'armv7') \
			export GOARCH='arm' GOARM='7' GOOS='linux'; \
			;; \
		'aarch64') \
			export GOARCH='arm64' GOOS='linux'; \
			;; \
		'x86') \
			export GO386='softfloat' GOARCH='386' GOOS='linux'; \
			;; \
		'ppc64le') \
			export GOARCH='ppc64le' GOOS='linux'; \
			;; \
		's390x') \
			export GOARCH='s390x' GOOS='linux'; \
			;; \
		*) echo >&2 "error: unsupported architecture '$arch' (likely packaging update needed)"; exit 1 ;; \
	esac; \
# the precompiled binaries published by Go upstream are not compatible with Alpine, so we always build from source here 😅
	apk add --no-cache --virtual .build-deps \
		bash \
		gcc \
		go \
		musl-dev \
	; \
	\
	cd /usr/local/go/src; \
# set GOROOT_BOOTSTRAP + GOHOST* such that we can build Go successfully
	export GOROOT_BOOTSTRAP="$(go env GOROOT)" GOHOSTOS="$GOOS" GOHOSTARCH="$GOARCH"; \
	GOFLAGS="-tags=\""$GO_TAGS"\"" ./make.bash; \
	\
	apk del --no-network .build-deps; \
	\
# remove a few intermediate / bootstrapping files the official binary release tarballs do not contain
	rm -rf \
		/usr/local/go/pkg/*/cmd \
		/usr/local/go/pkg/bootstrap \
		/usr/local/go/pkg/obj \
		/usr/local/go/pkg/tool/*/api \
		/usr/local/go/pkg/tool/*/go_bootstrap \
		/usr/local/go/src/cmd/dist/dist \
	; \
	go version

ENV GOPATH /go
ENV PATH $GOPATH/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
WORKDIR $GOPATH
