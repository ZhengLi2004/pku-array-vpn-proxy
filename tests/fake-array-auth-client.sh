#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Emits deterministic auth-sidecar cookies and failure classes for driver tests.
set -eu

case ${1:-} in
--healthcheck | --invalidate)
	exit 0
	;;
192.0.2.1)
	if [ "${FAKE_AUTH_PERMANENT:-0}" = 1 ]; then
		printf '%s\n' 'ARRAY_AUTH_PERMANENT:AUTH_REJECTED' >&2
		exit 64
	fi

	if [ "${FAKE_AUTH_SILENT_PERMANENT:-0}" = 1 ]; then
		exit 64
	fi

	if [ "${FAKE_AUTH_TRANSIENT:-0}" = 1 ]; then
		printf '%s\n' 'ARRAY_AUTH_TRANSIENT:NETWORK' >&2
		exit 75
	fi

	if [ "${FAKE_AUTH_BAD_COOKIE:-0}" = 1 ]; then
		printf '%s\n' 'not-a-session-cookie'
		exit 0
	fi

	printf '%s\n' 'ANsessionFAKE=synthetic-cookie'
	;;
*)
	printf '%s\n' 'ARRAY_AUTH_PERMANENT:BAD_REQUEST' >&2
	exit 64
	;;
esac
