#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
# Reports whether the supervised SOCKS path has succeeded recently enough.
set -eu
state_dir=${ARRAY_STATE_DIR:-/run/arrayvpn/state}
status_file=$state_dir/status
last_ok_file=$state_dir/last_ok
stale_after=${HEALTHCHECK_STALE_AFTER:-190}
test -r "$status_file"
test -r "$last_ok_file"
test "$(cat "$status_file")" = healthy
last_ok=$(cat "$last_ok_file")

case "$last_ok" in
'' | *[!0-9]*) exit 1 ;;
esac

now=$(date +%s)
test $((now - last_ok)) -le "$stale_after"
