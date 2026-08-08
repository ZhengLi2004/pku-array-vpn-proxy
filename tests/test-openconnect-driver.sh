#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Exercises the Expect driver against synthetic auth and OpenConnect programs.
set -Eeuo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)
image=${IMAGE:-${PKU_ARRAY_VPN_IMAGE:-pku-array-vpn-proxy:local}}
fake_openconnect=$repo_dir/tests/fake-openconnect.sh
fake_auth_client=$repo_dir/tests/fake-array-auth-client.sh
driver_under_test=$repo_dir/scripts/openconnect-driver.exp
runtime_uid=$(id -u)
runtime_gid=$(id -g)

[[ $runtime_uid -ne 0 && $runtime_gid -ne 0 ]] || {
	echo 'OpenConnect driver tests require a non-root user and group.' >&2
	exit 64
}

common_args=(
	--rm
	--network none
	--read-only
	--user "$runtime_uid:$runtime_gid"
	--cap-drop ALL
	--security-opt no-new-privileges:true
	--tmpfs "/run/arrayvpn:rw,noexec,nosuid,nodev,mode=0700,uid=$runtime_uid,gid=$runtime_gid"
	--mount type=bind,src="$fake_openconnect",dst=/usr/local/sbin/openconnect,readonly
	--mount type=bind,src="$fake_auth_client",dst=/usr/local/bin/array-auth-client,readonly
	--mount type=bind,src="$driver_under_test",dst=/usr/local/bin/openconnect-driver.exp,readonly
)

driver_output=$(
	docker run "${common_args[@]}" \
		--entrypoint /usr/local/bin/openconnect-driver.exp \
		"$image" 192.0.2.1
)

[[ $driver_output == *'Connected to HTTPS on fake.invalid with ciphersuite TEST'* ]]

if [[ $driver_output == *'synthetic-cookie'* ]]; then
	echo 'OpenConnect driver echoed the synthetic session cookie' >&2
	exit 1
fi

set +e

certificate_output=$(
	docker run "${common_args[@]}" \
		--env FAKE_CERT_REJECT=1 \
		--entrypoint /usr/local/bin/openconnect-driver.exp \
		"$image" 192.0.2.1 2>&1
)

certificate_status=$?
set -e
[[ $certificate_status -eq 64 ]]
[[ $certificate_output == *'Server certificate verify failed'* ]]
[[ $certificate_output != *'synthetic-cookie'* ]]
set +e

auth_permanent_output=$(
	docker run "${common_args[@]}" \
		--env FAKE_AUTH_PERMANENT=1 \
		--entrypoint /usr/local/bin/openconnect-driver.exp \
		"$image" 192.0.2.1 2>&1
)

auth_permanent_status=$?
set -e
[[ $auth_permanent_status -eq 64 ]]
[[ $auth_permanent_output == 'ARRAY_AUTH_PERMANENT:AUTH_REJECTED' ]]
set +e

silent_permanent_output=$(
	docker run "${common_args[@]}" \
		--env FAKE_AUTH_SILENT_PERMANENT=1 \
		--entrypoint /usr/local/bin/openconnect-driver.exp \
		"$image" 192.0.2.1 2>&1
)

silent_permanent_status=$?
set -e
[[ $silent_permanent_status -eq 64 ]]
[[ $silent_permanent_output == 'ARRAY_AUTH_PERMANENT:CLIENT' ]]
set +e

auth_transient_output=$(
	docker run "${common_args[@]}" \
		--env FAKE_AUTH_TRANSIENT=1 \
		--entrypoint /usr/local/bin/openconnect-driver.exp \
		"$image" 192.0.2.1 2>&1
)

auth_transient_status=$?
set -e
[[ $auth_transient_status -eq 75 ]]
[[ $auth_transient_output == 'ARRAY_AUTH_TRANSIENT:NETWORK' ]]
set +e

bad_cookie_output=$(
	docker run "${common_args[@]}" \
		--env FAKE_AUTH_BAD_COOKIE=1 \
		--entrypoint /usr/local/bin/openconnect-driver.exp \
		"$image" 192.0.2.1 2>&1
)

bad_cookie_status=$?
set -e
[[ $bad_cookie_status -eq 64 ]]
[[ $bad_cookie_output == 'ARRAY_AUTH_PERMANENT:COOKIE' ]]
set +e

session_rejected_output=$(
	docker run "${common_args[@]}" \
		--env FAKE_COOKIE_REJECT=1 \
		--entrypoint /usr/local/bin/openconnect-driver.exp \
		"$image" 192.0.2.1 2>&1
)

session_rejected_status=$?
set -e
[[ $session_rejected_status -eq 65 ]]
[[ $session_rejected_output == *'Cookie was rejected by server; exiting.'* ]]
echo 'openconnect_driver_test=ok'
