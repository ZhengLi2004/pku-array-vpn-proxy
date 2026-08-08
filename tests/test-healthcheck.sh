#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests fresh, stale, malformed, and non-healthy supervisor state files.
set -Eeuo pipefail
healthcheck=${1:-scripts/healthcheck.sh}
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
install -d -m 0700 "$repo_dir/artifacts"
test_root=$(mktemp -d "$repo_dir/artifacts/.health-test.XXXXXX")

# Removes only the randomized health-check fixture directory.
cleanup() {
	case "$test_root" in
	"$repo_dir"/artifacts/.health-test.*) rm -rf -- "$test_root" ;;
	*) echo 'refusing unsafe test cleanup' >&2 ;;
	esac
}

trap cleanup EXIT HUP INT TERM
printf 'healthy\n' >"$test_root/status"
date +%s >"$test_root/last_ok"
ARRAY_STATE_DIR=$test_root HEALTHCHECK_STALE_AFTER=190 "$healthcheck"
printf '%s\n' "$(($(date +%s) - 191))" >"$test_root/last_ok"

if ARRAY_STATE_DIR=$test_root HEALTHCHECK_STALE_AFTER=190 \
	"$healthcheck"; then
	echo 'stale health timestamp was accepted' >&2
	exit 1
fi

date +%s >"$test_root/last_ok"
printf 'permanent\n' >"$test_root/status"

if ARRAY_STATE_DIR=$test_root "$healthcheck"; then
	echo 'permanent status was accepted as healthy' >&2
	exit 1
fi

printf 'healthy\n' >"$test_root/status"
printf 'not-a-number\n' >"$test_root/last_ok"

if ARRAY_STATE_DIR=$test_root "$healthcheck"; then
	echo 'malformed timestamp was accepted' >&2
	exit 1
fi

echo 'healthcheck_test=ok'
