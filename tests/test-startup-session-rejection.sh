#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Verifies that a rejected startup cookie cannot trigger repeated authentication.
set -Eeuo pipefail
umask 077
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)
image=${IMAGE:-${PKU_ARRAY_VPN_IMAGE:-pku-array-vpn-proxy:local}}
entrypoint_under_test=${ENTRYPOINT_UNDER_TEST:-}
entrypoint_args=()
runtime_uid=$(id -u)
runtime_gid=$(id -g)

[[ $runtime_uid -ne 0 && $runtime_gid -ne 0 ]] || {
	echo 'Startup rejection tests require a non-root user and group.' >&2
	exit 64
}

if [[ -n $entrypoint_under_test ]]; then
	[[ -f $entrypoint_under_test && ! -L $entrypoint_under_test ]] || {
		echo 'ENTRYPOINT_UNDER_TEST must name a regular non-symlink file' >&2
		exit 64
	}

	entrypoint_under_test=$(realpath -- "$entrypoint_under_test")

	entrypoint_args=(
		--mount
		"type=bind,src=$entrypoint_under_test,dst=/usr/local/bin/entrypoint.sh,readonly"
	)
fi

test_dir=$(mktemp -d "$repo_dir/artifacts/.session-rejection.XXXXXX")
container_name=pku-array-session-rejection-$$
started=0

# Removes the synthetic container and every mounted fixture file.
cleanup() {
	if ((started)); then
		docker rm --force "$container_name" >/dev/null 2>&1 || :
	fi

	rm -rf -- "$test_dir"
}

trap cleanup EXIT HUP INT TERM

cat >"$test_dir/resolve-array.sh" <<'EOF'
#!/bin/sh
printf '%s\n' '192.0.2.1'
EOF

cat >"$test_dir/verify-gateway-pin.sh" <<'EOF'
#!/bin/sh
printf '%s\n' "$1"
EOF

cat >"$test_dir/openconnect-driver.exp" <<'EOF'
#!/bin/sh
printf '%s\n' '1' >>/run/arrayvpn/state/driver-invocations
printf '%s\n' 'Cookie was rejected by server; exiting.'
exit 65
EOF

chmod 0755 "$test_dir/resolve-array.sh" \
	"$test_dir/verify-gateway-pin.sh" "$test_dir/openconnect-driver.exp"

started=1

docker run --detach --name "$container_name" \
	--network none --read-only --user "$runtime_uid:$runtime_gid" \
	--cap-drop ALL --security-opt no-new-privileges:true \
	--no-healthcheck \
	--tmpfs "/run/arrayvpn:rw,noexec,nosuid,nodev,mode=0700,uid=$runtime_uid,gid=$runtime_gid" \
	--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777 \
	--mount type=bind,src="$test_dir/resolve-array.sh",dst=/usr/local/bin/resolve-array.sh,readonly \
	--mount type=bind,src="$test_dir/verify-gateway-pin.sh",dst=/usr/local/bin/verify-gateway-pin.sh,readonly \
	--mount type=bind,src="$test_dir/openconnect-driver.exp",dst=/usr/local/bin/openconnect-driver.exp,readonly \
	"${entrypoint_args[@]}" \
	"$image" >/dev/null

for _attempt in $(seq 1 50); do
	if docker exec "$container_name" sh -c \
		'test "$(cat /run/arrayvpn/state/status)" = permanent' \
		>/dev/null 2>&1; then
		break
	fi

	sleep 0.1
done

docker exec "$container_name" sh -eu -c '
	test "$(cat /run/arrayvpn/state/status)" = permanent
	test "$(cat /run/arrayvpn/state/reason)" = SESSION_REJECTED_BEFORE_HEALTHY
	test "$(wc -l </run/arrayvpn/state/driver-invocations)" = 1
'

sleep 1

docker exec "$container_name" sh -eu -c \
	'test "$(wc -l </run/arrayvpn/state/driver-invocations)" = 1'

docker logs "$container_name" >"$test_dir/container.log" 2>&1

grep -Fq 'reason=SESSION_REJECTED_BEFORE_HEALTHY' \
	"$test_dir/container.log"

if grep -Fq 'reason=AUTH_OR_CONFIG' "$test_dir/container.log"; then
	echo 'specific startup rejection reason was overwritten' >&2
	exit 1
fi

echo 'startup_session_rejection_test=ok'
