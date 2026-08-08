#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Exercises the compatibility adapter with synthetic SDK libraries only.
set -Eeuo pipefail
umask 077
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)
install -d -m 0700 "$repo_dir/artifacts"
test_dir=$(mktemp -d "$repo_dir/artifacts/.isecsp-auth-test.XXXXXX")
server_pid=
test_ok=0
port=19081

# Stops the synthetic server and preserves diagnostics only after a failure.
cleanup() {
	if [[ -n $server_pid ]] && kill -0 "$server_pid" 2>/dev/null; then
		kill -TERM "$server_pid" 2>/dev/null || :
		wait "$server_pid" 2>/dev/null || :
	fi

	if ((test_ok)); then
		rm -rf -- "$test_dir"
	else
		printf 'synthetic auth-helper diagnostics preserved at %s\n' \
			"$test_dir" >&2
	fi
}

trap cleanup EXIT HUP INT TERM

# Reports one synthetic authentication regression and exits.
fail() {
	printf 'isecsp auth-helper test failed: %s\n' "$*" >&2
	exit 1
}

compile_flags=(
	-std=c11 -O2 -g -Wall -Wextra -Werror -Wpedantic
	-fno-common -fstack-protector-strong -D_FORTIFY_SOURCE=2
	-Wformat=2 -Wconversion -Wshadow
)

link_flags=(-Wl,-z,relro,-z,now)
mkdir -m 0700 "$test_dir/secrets"
printf 'synthetic-user' >"$test_dir/secrets/vpn_username"
printf 'synthetic-password' >"$test_dir/secrets/vpn_password"
printf '12345X' >"$test_dir/secrets/id_card_last6"
printf '6789' >"$test_dir/secrets/phone_missing4"
chmod 0600 "$test_dir/secrets"/*

printf '%s\n' \
	'pin-sha256:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=' \
	>"$test_dir/good-pins.txt"

printf '%s\n' \
	'pin-sha256://////////////////////////////////////////8=' \
	>"$test_dir/bad-pins.txt"

cc "${compile_flags[@]}" -fPIC -shared \
	"$repo_dir/tests/fake-libisec.c" \
	-o "$test_dir/libisec.so"

cc "${compile_flags[@]}" -fPIC -shared \
	"$repo_dir/tests/fake-libvl3vpn.c" \
	-o "$test_dir/libvl3vpn.so"

cc "${compile_flags[@]}" \
	-DPKU_AUTH_PORT="$port" \
	-DISEC_LIBRARY_PATH="\"$test_dir/libisec.so\"" \
	-DISECSP_LIBRARY_PATH="\"$test_dir/libvl3vpn.so\"" \
	-DISEC_TEST_DYNAMIC_TLS_SYMBOLS=1 \
	-DPIN_FILE_PATH="\"$test_dir/good-pins.txt\"" \
	-DSECRET_DIRECTORY="\"$test_dir/secrets\"" \
	-Wl,--export-dynamic "${link_flags[@]}" -pthread \
	"$repo_dir/src/isecsp-auth/server.c" -ldl \
	-o "$test_dir/server-good-pin"

cc "${compile_flags[@]}" \
	-DPKU_AUTH_PORT="$port" \
	-DISEC_LIBRARY_PATH="\"$test_dir/libisec.so\"" \
	-DISECSP_LIBRARY_PATH="\"$test_dir/libvl3vpn.so\"" \
	-DISEC_TEST_DYNAMIC_TLS_SYMBOLS=1 \
	-DPIN_FILE_PATH="\"$test_dir/bad-pins.txt\"" \
	-DSECRET_DIRECTORY="\"$test_dir/secrets\"" \
	-Wl,--export-dynamic "${link_flags[@]}" -pthread \
	"$repo_dir/src/isecsp-auth/server.c" -ldl \
	-o "$test_dir/server-bad-pin"

cc "${compile_flags[@]}" -DPKU_AUTH_PORT="$port" \
	"${link_flags[@]}" "$repo_dir/src/auth-ipc/client.c" \
	-o "$test_dir/client"

readelf -Wr "$test_dir/libvl3vpn.so" >"$test_dir/libvl3vpn-relocations.txt"

grep -Eq 'JUMP_SLOT.*SSL_connect' "$test_dir/libvl3vpn-relocations.txt" ||
	fail 'fake SDK does not use a preemptible SSL_connect relocation'

readelf -Ws "$test_dir/server-good-pin" >"$test_dir/server-symbols.txt"

grep -Eq '[[:space:]]SSL_connect$' "$test_dir/server-symbols.txt" ||
	fail 'server does not export the SSL_connect guard'

# Starts one synthetic SDK scenario and waits for its IPC endpoint.
#
# Args:
#   $1: Synthetic authentication scenario name.
#   $2: Optional server binary; defaults to the good-pin fixture.
start_server() {
	local scenario=$1 binary=${2:-$test_dir/server-good-pin}
	local attempt

	: >"$test_dir/server.log"
	rm -f -- "$test_dir/ssl-connect.marker" "$test_dir/ssl-write.marker" \
		"$test_dir/isec-connect.marker" "$test_dir/isec-write.marker" \
		"$test_dir/post-success-mauth.marker"

	FAKE_SCENARIO=$scenario \
		FAKE_EXPECT_CANDIDATE=8.8.8.8 \
		FAKE_SSL_CONNECT_MARKER="$test_dir/ssl-connect.marker" \
		FAKE_SSL_WRITE_MARKER="$test_dir/ssl-write.marker" \
		FAKE_ISEC_CONNECT_MARKER="$test_dir/isec-connect.marker" \
		FAKE_ISEC_WRITE_MARKER="$test_dir/isec-write.marker" \
		FAKE_POST_SUCCESS_MAUTH_MARKER="$test_dir/post-success-mauth.marker" \
		"$binary" >"$test_dir/server.log" 2>&1 &

	server_pid=$!

	for attempt in {1..50}; do
		if "$test_dir/client" --healthcheck \
			>"$test_dir/health.out" 2>"$test_dir/health.err"; then
			return
		fi

		kill -0 "$server_pid" 2>/dev/null ||
			fail "server exited during startup for $scenario"
		sleep 0.05
	done

	fail "server did not become ready for $scenario"
}

# Stops and reaps the active synthetic authentication server.
stop_server() {
	if [[ -n $server_pid ]]; then
		kill -TERM "$server_pid" 2>/dev/null || :
		wait "$server_pid" 2>/dev/null || :
		server_pid=
	fi
}

# Runs the IPC client once and requires the expected process status.
#
# Args:
#   $1: Expected client exit status.
run_client() {
	local expected_status=$1
	set +e

	"$test_dir/client" 8.8.8.8 \
		>"$test_dir/client.out" 2>"$test_dir/client.err"

	client_status=$?
	set -e

	[[ $client_status -eq $expected_status ]] ||
		fail "client status $client_status, expected $expected_status"
}

# Requires one synthetic scenario to authenticate through the TLS guards.
#
# Args:
#   $1: Synthetic authentication scenario name.
run_success() {
	local scenario=$1
	start_server "$scenario"
	run_client 0

	grep -Fqx 'ANsessionFAKE=abc=123' "$test_dir/client.out" ||
		fail "scenario $scenario returned the wrong cookie"

	[[ -s $test_dir/ssl-connect.marker && -s $test_dir/ssl-write.marker ]] ||
		fail "scenario $scenario did not traverse the TLS guards"

	stop_server
}

# Requires one synthetic scenario to latch the expected permanent failure.
#
# Args:
#   $1: Synthetic authentication scenario name.
#   $2: Expected sanitized permanent-failure reason.
run_permanent() {
	local scenario=$1 reason=$2
	start_server "$scenario"
	run_client 64

	grep -Fqx "ARRAY_AUTH_PERMANENT:$reason" "$test_dir/client.err" ||
		fail "scenario $scenario was not classified as $reason"

	set +e

	"$test_dir/client" --healthcheck \
		>"$test_dir/latch.out" 2>"$test_dir/latch.err"

	latch_status=$?
	set -e

	[[ $latch_status -eq 64 ]] ||
		fail "scenario $scenario did not latch permanent state"

	stop_server
}

for scenario in \
	none write-ex isec-net mauth-after-success id id-variant phone phone-position dual \
	announced-id announced-phone announced-dual announced-description-dual \
	announced-server-wins announced-unused-malformed-description \
	sole-radius-alias; do
	run_success "$scenario"

	if [[ $scenario == isec-net ]]; then
		[[ -s $test_dir/isec-connect.marker &&
			-s $test_dir/isec-write.marker ]] ||
			fail 'verified libisec network path did not reach its fake transport'
	fi

	if [[ $scenario == mauth-after-success ]]; then
		[[ ! -e $test_dir/post-success-mauth.marker ]] ||
			fail 'SDK continued into device-certificate auth after Cookie success'
	fi
done

run_permanent bad-password AUTH_REJECTED
run_permanent unknown UNKNOWN_CHALLENGE
run_permanent ambiguous UNKNOWN_CHALLENGE
run_permanent repeat REPEATED_CHALLENGE
run_permanent sms UNKNOWN_CHALLENGE
run_permanent duplicate-method METHOD_SELECTION
run_permanent wrong-method METHOD_SELECTION
run_permanent method-description-only METHOD_SELECTION
run_permanent malformed-method-name METHOD_NAME
run_permanent zero-method METHOD_COUNT
run_permanent too-many-methods METHOD_COUNT
run_permanent mauth MAUTH
run_permanent too-many-announced METHOD_STEPS
run_permanent unknown-announced METHOD_STEPS
run_permanent unknown-server-known-description METHOD_STEPS
run_permanent duplicate-announced METHOD_STEPS
run_permanent malformed-announced METHOD_STEPS
run_permanent announced-dual-repeat REPEATED_CHALLENGE
run_permanent success-before-primary METHOD_SEQUENCE
run_permanent success-error AUTH_REJECTED
run_permanent repeat-primary METHOD_SEQUENCE
run_permanent initial-error METHOD_CALLBACK_ERROR
run_permanent null-initial METHOD_INPUT_NULL
run_permanent short-initial METHOD_INPUT_LENGTH
run_permanent null-output METHOD_OUTPUT_NULL
run_permanent null-output-length METHOD_OUTPUT_LENGTH_NULL
run_permanent short-output METHOD_OUTPUT_CAPACITY
run_permanent placeholder COOKIE
run_permanent multiple-cookie COOKIE
run_permanent control-cookie COOKIE
run_permanent cookie-api-error COOKIE
start_server network
run_client 75

grep -Fqx 'ARRAY_AUTH_TRANSIENT:NETWORK' "$test_dir/client.err" ||
	fail 'pre-credential network failure was not transient'

stop_server
start_server isec-write-before-connect
run_client 64

grep -Fqx 'ARRAY_AUTH_PERMANENT:CERTIFICATE' "$test_dir/client.err" ||
	fail 'unverified libisec write was not classified as a certificate error'

[[ ! -e $test_dir/isec-write.marker ]] ||
	fail 'unverified libisec write reached the fake transport'

stop_server
start_server isec-null-write
run_client 64

grep -Fqx 'ARRAY_AUTH_PERMANENT:CERTIFICATE' "$test_dir/client.err" ||
	fail 'null libisec network was not classified as a certificate error'

[[ ! -e $test_dir/isec-write.marker ]] ||
	fail 'null libisec network reached the fake transport'

stop_server
start_server write-before-pin
run_client 64

grep -Fqx 'ARRAY_AUTH_PERMANENT:CERTIFICATE' "$test_dir/client.err" ||
	fail 'write-before-pin did not fail as a certificate error'

[[ ! -e $test_dir/ssl-write.marker ]] ||
	fail 'unverified TLS write reached the fake SDK implementation'

stop_server
start_server null-ssl-write
run_client 64

grep -Fqx 'ARRAY_AUTH_PERMANENT:CERTIFICATE' "$test_dir/client.err" ||
	fail 'null SSL was not classified as a certificate error'

[[ ! -e $test_dir/ssl-write.marker ]] ||
	fail 'null SSL reached the fake SDK implementation'

stop_server
start_server isec-net-bad-pin "$test_dir/server-bad-pin"
run_client 64

grep -Fqx 'ARRAY_AUTH_PERMANENT:CERTIFICATE' "$test_dir/client.err" ||
	fail 'wrong libisec pin was not classified as a certificate error'

[[ -s $test_dir/isec-connect.marker ]] ||
	fail 'wrong libisec pin test did not complete the fake handshake'

[[ ! -e $test_dir/isec-write.marker ]] ||
	fail 'libisec application data was written after a pin mismatch'

stop_server
start_server write-ex-before-pin
run_client 64

grep -Fqx 'ARRAY_AUTH_PERMANENT:CERTIFICATE' "$test_dir/client.err" ||
	fail 'write-ex-before-pin did not fail as a certificate error'

[[ ! -e $test_dir/ssl-write.marker ]] ||
	fail 'unverified SSL_write_ex reached the fake SDK implementation'

stop_server
start_server clear-before-write
run_client 64

grep -Fqx 'ARRAY_AUTH_PERMANENT:CERTIFICATE' "$test_dir/client.err" ||
	fail 'write after SSL_clear did not fail as a certificate error'

[[ ! -e $test_dir/ssl-write.marker ]] ||
	fail 'TLS write remained authorized after SSL_clear'

stop_server
start_server none "$test_dir/server-bad-pin"
run_client 64

grep -Fqx 'ARRAY_AUTH_PERMANENT:CERTIFICATE' "$test_dir/client.err" ||
	fail 'wrong pin did not fail as a certificate error'

[[ -s $test_dir/ssl-connect.marker ]] ||
	fail 'wrong-pin test did not complete the synthetic handshake'

[[ ! -e $test_dir/ssl-write.marker ]] ||
	fail 'application data was written after a pin mismatch'

stop_server
start_server none
run_client 0
rm -f -- "$test_dir/ssl-connect.marker" "$test_dir/ssl-write.marker"
run_client 0

grep -Fqx 'ANsessionFAKE=abc=123' "$test_dir/client.out" ||
	fail 'cached session did not return the same cookie'

[[ ! -e $test_dir/ssl-connect.marker && ! -e $test_dir/ssl-write.marker ]] ||
	fail 'cached session triggered a second SDK authentication'

"$test_dir/client" --invalidate >/dev/null 2>"$test_dir/invalidate.err" ||
	fail 'cache invalidation failed'

stop_server

if grep -nE 'synthetic-(user|password)|12345X|6789|ANsessionFAKE' \
	"$test_dir/server.log"; then
	fail 'server log contains a synthetic secret or cookie'
fi

test_ok=1
printf 'isecsp auth-helper tests: ok\n'
