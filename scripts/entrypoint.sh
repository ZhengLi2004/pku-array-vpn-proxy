#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Supervises gateway resolution, pinned Array transport, and SOCKS health.
set -Eeuo pipefail
umask 077
readonly state_dir=/run/arrayvpn/state
readonly candidates_file=/run/arrayvpn/candidates
readonly socks_endpoint=127.0.0.1:1080
readonly pin_file=/etc/arrayvpn/servercert-pins.txt
readonly array_host=arrayvpn.pku.edu.cn
health_url=${HEALTHCHECK_URL:-https://its.pku.edu.cn/service_1_vpn2.jsp}
health_interval=${HEALTHCHECK_INTERVAL:-60}
health_max_fails=${HEALTHCHECK_MAX_FAILS:-3}
health_start_timeout=${HEALTHCHECK_START_TIMEOUT:-180}
driver_pid=
driver_exit=75
backoff_index=0
candidate_cursor=0
auth_cache_needs_invalidation=0
backoff_steps=(5 15 30 60 120 300)
mkdir -p "$state_dir"

# Writes one timestamped, credential-free supervisor event.
log() {
	printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

# Atomically publishes the current lifecycle state for the health check.
write_status() {
	local new_status=$1
	local status_tmp=$state_dir/status.$$
	printf '%s\n' "$new_status" >"$status_tmp"
	mv -f -- "$status_tmp" "$state_dir/status"
}

# Atomically records the epoch of the latest successful SOCKS probe.
write_last_ok() {
	local timestamp_tmp=$state_dir/last_ok.$$
	date +%s >"$timestamp_tmp"
	mv -f -- "$timestamp_tmp" "$state_dir/last_ok"
}

# Atomically records one fixed failure reason for operator diagnostics.
write_reason() {
	local reason=$1
	local reason_tmp=$state_dir/reason.$$
	printf '%s\n' "$reason" >"$reason_tmp"
	mv -f -- "$reason_tmp" "$state_dir/reason"
}

# Reaps the OpenConnect driver and captures its normalized process status.
reap_driver() {
	driver_exit=75

	if [[ -n $driver_pid ]]; then
		set +e
		wait "$driver_pid"
		driver_exit=$?
		set -e
		driver_pid=
	fi
}

# Terminates and reaps the current OpenConnect driver when one is running.
stop_driver() {
	if [[ -n $driver_pid ]] && kill -0 "$driver_pid" 2>/dev/null; then
		kill -TERM "$driver_pid" 2>/dev/null || :
	fi

	reap_driver
}

# Marks an operator-requested shutdown before stopping the tunnel process.
on_signal() {
	write_status stopped
	stop_driver
	exit 0
}

trap on_signal TERM INT

# Latches an unrecoverable state without restarting or resubmitting credentials.
#
# Args:
#   $1: Fixed sanitized reason stored for the container health check.
#
# Side effects:
#   Marks the service permanent/unhealthy and sleeps until an operator stops it.
permanent_wait() {
	local reason=$1
	write_reason "$reason"
	write_status permanent
	log "state=permanent reason=$reason; waiting for manual correction and restart"

	while true; do
		sleep 3600 &
		wait $! || :
	done
}

# Validates one bounded unsigned configuration value.
#
# Args:
#   $1: Diagnostic field name.
#   $2: Candidate decimal value.
#   $3: Inclusive minimum.
#   $4: Inclusive maximum.
#
# Returns:
#   Zero when valid. Invalid input enters permanent_wait and does not return.
validate_uint() {
	local name=$1 value=$2 minimum=$3 maximum=$4

	if [[ ! $value =~ ^[0-9]+$ ]] ||
		((value < minimum || value > maximum)); then
		permanent_wait "CONFIG_$name"
	fi
}

# Validates all runtime settings before DNS, TLS, or authentication begins.
#
# Side effects:
#   Invalid configuration enters permanent_wait before any credential request.
validate_configuration() {
	if [[ $(id -u) -eq 0 ]] || [[ $(id -g) -eq 0 ]]; then
		permanent_wait RUNTIME_IDENTITY
	fi

	if [[ ! $health_url =~ ^https://[^[:space:]]+$ ]]; then
		permanent_wait HEALTH_URL
	fi

	validate_uint HEALTH_INTERVAL "$health_interval" 10 3600
	validate_uint HEALTH_MAX_FAILS "$health_max_fails" 1 10
	validate_uint HEALTH_START_TIMEOUT "$health_start_timeout" 30 600

	if [[ ! -f $pin_file ]] || [[ -L $pin_file ]]; then
		permanent_wait PIN_FILE
	fi
}

# Checks the SOCKS data path while delegating DNS resolution to the proxy.
#
# Returns:
#   Curl's success status; response data is discarded and never logged.
probe_socks() {
	curl --fail --silent --show-error \
		--connect-timeout 10 --max-time 20 \
		--socks5-hostname "$socks_endpoint" \
		--head "$health_url" >/dev/null 2>&1
}

# Runs and supervises one verified gateway candidate until it must be replaced.
#
# Args:
#   $1: Public IPv4 already accepted by the SPKI preflight.
#   $2: Human-readable one-based candidate number for sanitized logs.
#
# Returns:
#   64 for permanent auth/config failure, 66 for a session rejected before
#   first health, or 75 for a retryable network/session failure.
#
# Globals:
#   Updates driver_pid, driver_exit, backoff_index, and
#   auth_cache_needs_invalidation.
run_candidate() {
	local candidate_ip=$1 candidate_number=$2
	local deadline now connected_at fail_count=0 was_healthy=0
	write_status connecting
	log "state=connecting candidate=$candidate_number"
	/usr/local/bin/openconnect-driver.exp "$candidate_ip" &
	driver_pid=$!
	deadline=$(($(date +%s) + health_start_timeout))

	while kill -0 "$driver_pid" 2>/dev/null; do
		if probe_socks; then
			connected_at=$(date +%s)
			write_last_ok
			write_status healthy
			was_healthy=1
			log "state=healthy candidate=$candidate_number"
			break
		fi

		now=$(date +%s)

		if ((now >= deadline)); then
			stop_driver

			if ((driver_exit == 64)); then
				return 64
			fi

			if ((driver_exit == 65)); then
				return 66
			fi

			log "state=transient reason=START_TIMEOUT candidate=$candidate_number"
			return 75
		fi

		sleep 2
	done

	if ! kill -0 "$driver_pid" 2>/dev/null; then
		reap_driver

		if ((driver_exit == 64)); then
			return 64
		fi

		if ((driver_exit == 65)); then
			return 66
		fi

		return 75
	fi

	while kill -0 "$driver_pid" 2>/dev/null; do
		sleep "$health_interval"

		if ! kill -0 "$driver_pid" 2>/dev/null; then
			break
		fi

		if probe_socks; then
			fail_count=0
			write_last_ok
			continue
		fi

		fail_count=$((fail_count + 1))
		log "state=degraded failures=$fail_count/$health_max_fails"

		if ((fail_count >= health_max_fails)); then
			stop_driver

			if ((driver_exit == 64)); then
				return 64
			fi

			if ((driver_exit == 65)); then
				log "state=transient reason=SESSION_EXPIRED candidate=$candidate_number"
			else
				log "state=transient reason=HEALTH_FAILURES"
			fi

			now=$(date +%s)
			auth_cache_needs_invalidation=1

			if ((now - connected_at >= 300)); then
				backoff_index=0
			fi

			return 75
		fi
	done

	reap_driver
	now=$(date +%s)

	if ((now - connected_at >= 300)); then
		backoff_index=0
	fi

	if ((driver_exit == 64)); then
		return 64
	fi

	if ((was_healthy)); then
		auth_cache_needs_invalidation=1
	fi

	if ((driver_exit == 65)); then
		log "state=transient reason=SESSION_EXPIRED candidate=$candidate_number"
	fi

	return 75
}

# Sleeps for the current retry slot and advances the capped backoff schedule.
#
# Globals:
#   Reads backoff_steps and updates backoff_index and the persisted status.
sleep_backoff() {
	local base=${backoff_steps[$backoff_index]}
	write_status backoff
	log "state=backoff delay=$base"
	sleep "$base"

	if ((backoff_index < ${#backoff_steps[@]} - 1)); then
		backoff_index=$((backoff_index + 1))
	fi
}

validate_configuration
write_status starting
log "state=starting protocol=array socks=127.0.0.1:1080"

while true; do
	if ((auth_cache_needs_invalidation)); then
		set +e
		/usr/local/bin/array-auth-client --invalidate >/dev/null 2>&1
		invalidate_status=$?
		set -e

		if ((invalidate_status == 64)); then
			permanent_wait AUTH_SIDECAR
		elif ((invalidate_status != 0)); then
			log "state=transient reason=AUTH_CACHE_INVALIDATE"
			sleep_backoff
			continue
		fi

		auth_cache_needs_invalidation=0
	fi

	if ! /usr/local/bin/resolve-array.sh >"$candidates_file"; then
		sleep_backoff
		continue
	fi

	mapfile -t candidates <"$candidates_file"
	verified_candidates=()
	candidate_number=0

	for candidate_ip in "${candidates[@]}"; do
		candidate_number=$((candidate_number + 1))
		set +e
		verified_ip=$(/usr/local/bin/verify-gateway-pin.sh "$candidate_ip")
		verify_status=$?
		set -e

		if ((verify_status == 64)); then
			permanent_wait TLS_PIN_MISMATCH
		elif ((verify_status != 0)); then
			log "state=transient reason=TLS_PREFLIGHT candidate=$candidate_number"
			continue
		fi

		verified_candidates+=("$verified_ip")
	done

	if ((${#verified_candidates[@]} == 0)); then
		sleep_backoff
		continue
	fi

	selected_index=$((candidate_cursor % ${#verified_candidates[@]}))
	candidate_cursor=$((candidate_cursor + 1))

	if run_candidate "${verified_candidates[$selected_index]}" \
		"$((selected_index + 1))"; then
		candidate_status=0
	else
		candidate_status=$?
	fi

	if ((candidate_status == 64)); then
		permanent_wait AUTH_OR_CONFIG
	elif ((candidate_status == 66)); then
		permanent_wait SESSION_REJECTED_BEFORE_HEALTHY
	fi

	sleep_backoff
done
