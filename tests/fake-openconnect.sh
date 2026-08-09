#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Emulates bounded OpenConnect output and statuses for Expect-driver tests.
set -eu
cookie_mode=0
non_interactive=0
dtls_disabled=0
resolve=

for argument in "$@"; do
	if [ "$argument" = --cookie-on-stdin ]; then
		cookie_mode=1
	elif [ "$argument" = --non-inter ]; then
		non_interactive=1
	elif [ "$argument" = --no-dtls ]; then
		dtls_disabled=1
	elif [ "${argument#--resolve=}" != "$argument" ]; then
		[ -z "$resolve" ] || exit 2
		resolve=${argument#--resolve=}
	fi
done

[ "$cookie_mode" = 1 ] && [ "$non_interactive" = 1 ] || exit 2
[ "$resolve" = arrayvpn.pku.edu.cn:192.0.2.1 ] || exit 2

case ${VPN_DATA_TRANSPORT:-tls} in
tls) [ "$dtls_disabled" = 1 ] || exit 2 ;;
auto) [ "$dtls_disabled" = 0 ] || exit 2 ;;
*) exit 2 ;;
esac

printf '%s\n' 'Server certificate verify failed: signer not found'

if [ "${FAKE_CERT_REJECT:-0}" = 1 ]; then
	exit 1
fi

printf '%s\n' 'Connected to HTTPS on fake.invalid with ciphersuite TEST'
IFS= read -r session_cookie

case $session_cookie in
ANsession*=*) ;;
*) exit 1 ;;
esac

if [ "${FAKE_SESSION_ACCEPTED:-0}" = 1 ]; then
	printf '%s\n' 'Configured as 192.0.2.10, with SSL connected and DTLS disabled'
fi

if [ "${FAKE_COOKIE_REJECT:-0}" = 1 ]; then
	printf '%s\n' 'Cookie was rejected by server; exiting.' >&2
	exit 1
fi
