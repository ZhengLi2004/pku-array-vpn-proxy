# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# SPDX-License-Identifier: Apache-2.0
# Builds the pinned OpenConnect and ocproxy SOCKS runtime without VPN privileges.

# Compiles and stages the locked tunnel components and auth IPC client.
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS builder
ARG OPENCONNECT_COMMIT=8b702bf2dbaf11302ed98629214b1df5d50a12aa
ARG OCPROXY_COMMIT=c98f06d942970cdf35dd66ab46840f7d6d567b60
ARG OCPROXY_PERFORMANCE_PATCH_SHA256=beab1230018ac3fc3c9635a060b5c251a4c3707eee51c94425c309a1ed1232bf
ARG JQ_APK_VERSION=1.8.2-r0
ARG JQ_APK_SHA256=a2ec9dca2378a9e62e4bbb63ff7f0223e4ac5a6a53acac74889f8d15b91578d8
ARG ALPINE_MIRROR

RUN --mount=type=cache,id=apk-v3.24-x86_64,target=/var/cache/apk,sharing=locked \
     if test -n "$ALPINE_MIRROR"; then \
     printf '%s\n' \
     "${ALPINE_MIRROR%/}/v3.24/main" \
     "${ALPINE_MIRROR%/}/v3.24/community" \
     > /etc/apk/repositories; \
     fi \
     && apk add --cache-dir=/var/cache/apk \
     bash ca-certificates curl git make pkgconf python3

RUN package_repository="${ALPINE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine}" \
     && install -d -m 0755 /out/packages \
     && curl --fail --silent --show-error --location \
     --proto '=https' --tlsv1.2 \
     "${package_repository%/}/edge/main/x86_64/jq-${JQ_APK_VERSION}.apk" \
     -o "/out/packages/jq-${JQ_APK_VERSION}.apk" \
     && echo "${JQ_APK_SHA256}  /out/packages/jq-${JQ_APK_VERSION}.apk" | \
     sha256sum -c -

RUN --mount=type=cache,id=apk-v3.24-x86_64,target=/var/cache/apk,sharing=locked \
     apk add --cache-dir=/var/cache/apk \
     autoconf automake gettext-dev libtool

RUN --mount=type=cache,id=apk-v3.24-x86_64,target=/var/cache/apk,sharing=locked \
     apk add --cache-dir=/var/cache/apk \
     binutils gcc linux-headers musl-dev

RUN --mount=type=cache,id=apk-v3.24-x86_64,target=/var/cache/apk,sharing=locked \
     apk add --cache-dir=/var/cache/apk \
     gnutls-dev libevent-dev libxml2-dev lz4-dev zlib-dev

WORKDIR /build

RUN git init openconnect \
     && cd openconnect \
     && git remote add origin https://gitlab.com/openconnect/openconnect.git \
     && git fetch --depth=1 origin "$OPENCONNECT_COMMIT" \
     && git checkout --detach FETCH_HEAD \
     && test "$(git rev-parse HEAD)" = "$OPENCONNECT_COMMIT"

RUN cd /build/openconnect \
     && ./autogen.sh \
     && ./configure \
     --with-gnutls \
     --without-openssl \
     --disable-nls \
     --with-vpnc-script=/usr/local/bin/ocproxy \
     && make -j"$(getconf _NPROCESSORS_ONLN)" \
     && make check \
     && make DESTDIR=/out/openconnect install \
     && rm -rf \
     /out/openconnect/usr/local/include \
     /out/openconnect/usr/local/libexec \
     /out/openconnect/usr/local/share \
     && rm -f \
     /out/openconnect/usr/local/lib/*.la \
     && rm -rf \
     /out/openconnect/usr/local/lib/pkgconfig

COPY patches/ocproxy-upload-performance.patch /build/patches/ocproxy-upload-performance.patch

RUN test "$OCPROXY_PERFORMANCE_PATCH_SHA256" = "beab1230018ac3fc3c9635a060b5c251a4c3707eee51c94425c309a1ed1232bf" \
     && echo "$OCPROXY_PERFORMANCE_PATCH_SHA256  /build/patches/ocproxy-upload-performance.patch" | \
     sha256sum -c -

RUN test "$OCPROXY_COMMIT" = "c98f06d942970cdf35dd66ab46840f7d6d567b60" \
     && git init -q ocproxy \
     && cd /build/ocproxy \
     && git remote add origin https://github.com/cernekee/ocproxy.git \
     && fetched=0 \
     && for delay in 0 2 5 10; do \
     test "$delay" -eq 0 || sleep "$delay"; \
     if git -c http.version=HTTP/1.1 fetch --depth=1 --no-tags \
     origin "$OCPROXY_COMMIT"; then \
     fetched=1; \
     break; \
     fi; \
     done \
     && test "$fetched" -eq 1 \
     && git checkout --detach FETCH_HEAD \
     && test "$(git rev-parse HEAD)" = "$OCPROXY_COMMIT" \
     && git -C /build/ocproxy apply --check --whitespace=error-all \
     /build/patches/ocproxy-upload-performance.patch \
     && git -C /build/ocproxy apply --whitespace=error-all \
     /build/patches/ocproxy-upload-performance.patch \
     && git -C /build/ocproxy diff --check \
     && ./autogen.sh \
     && ./configure --disable-vpnns \
     && make -j"$(getconf _NPROCESSORS_ONLN)" \
     && make DESTDIR=/out/ocproxy install \
     && rm -rf \
     /out/ocproxy/usr/local/share

COPY src/auth-ipc/client.c src/auth-ipc/protocol.h /build/auth-client/

RUN cc -std=c11 -O2 -Wall -Wextra -Werror -Wpedantic \
     -Wformat=2 -Wconversion -Wshadow -fno-common \
     -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
     -Wl,-z,relro,-z,now \
     /build/auth-client/client.c -o /out/array-auth-client

# Assembles the non-root, source-free tunnel runtime image.
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
ARG ALPINE_MIRROR
LABEL org.opencontainers.image.title="PKU Array VPN SOCKS5 proxy"
LABEL org.opencontainers.image.description="Pinned OpenConnect Array plus ocproxy; loopback publication is configured by Compose"
LABEL org.opencontainers.image.source="https://github.com/ZhengLi2004/pku-array-vpn-proxy"
LABEL org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /out/packages/jq-1.8.2-r0.apk /tmp/jq-1.8.2-r0.apk

RUN if test -n "$ALPINE_MIRROR"; then \
     printf '%s\n' \
     "${ALPINE_MIRROR%/}/v3.24/main" \
     "${ALPINE_MIRROR%/}/v3.24/community" \
     > /etc/apk/repositories; \
     fi \
     && apk add --no-cache \
     bash ca-certificates curl expect gnutls gnutls-utils libevent \
     libgcc lz4-libs libxml2 oniguruma openssl zlib \
     && apk add --no-cache --no-network /tmp/jq-1.8.2-r0.apk \
     && rm -f /tmp/jq-1.8.2-r0.apk \
     && addgroup -S arrayvpn \
     && adduser -S -D -H -G arrayvpn arrayvpn

COPY --from=builder /out/openconnect/usr/local/ /usr/local/
COPY --from=builder /out/ocproxy/usr/local/ /usr/local/
COPY --from=builder /out/array-auth-client /usr/local/bin/array-auth-client

COPY --from=builder /build/openconnect/COPYING.LGPL \
     /usr/share/licenses/openconnect/COPYING.LGPL

COPY --from=builder /build/ocproxy/LICENSE \
     /usr/share/licenses/ocproxy/LICENSE

COPY --from=builder /build/ocproxy/AUTHORS \
     /usr/share/licenses/ocproxy/AUTHORS

COPY --from=builder /build/ocproxy/lwip/COPYING \
     /usr/share/licenses/lwip/COPYING

COPY --chmod=0755 scripts/entrypoint.sh scripts/openconnect-driver.exp \
     scripts/resolve-array.sh scripts/verify-gateway-pin.sh \
     scripts/healthcheck.sh scripts/inspect-certificates.sh \
     /usr/local/bin/

COPY config/servercert-pins.txt /etc/arrayvpn/servercert-pins.txt

COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md \
     /usr/share/licenses/pku-array-vpn-proxy/

ENV LD_LIBRARY_PATH=/usr/local/lib
USER arrayvpn:arrayvpn
WORKDIR /run/arrayvpn
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
