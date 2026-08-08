#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Emulates bounded OpenConnect output and statuses for Expect-driver tests.
set -eu
cookie_mode=0
non_interactive=0

for argument in "$@"; do
	if [ "$argument" = --cookie-on-stdin ]; then
		cookie_mode=1
	elif [ "$argument" = --non-inter ]; then
		non_interactive=1
	fi
done

[ "$cookie_mode" = 1 ] && [ "$non_interactive" = 1 ] || exit 2
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

if [ "${FAKE_COOKIE_REJECT:-0}" = 1 ]; then
	printf '%s\n' 'Cookie was rejected by server; exiting.' >&2
	exit 1
fi
