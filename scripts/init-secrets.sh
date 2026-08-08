#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Creates private credentials and synchronizes the non-root Compose identity.
set -Eeuo pipefail
set +x
umask 077
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)
secret_dir=$repo_dir/secrets
runtime_env=$repo_dir/.env
replace=0
sync_only=0

if [[ $# -eq 1 && $1 == --replace ]]; then
	replace=1
elif [[ $# -eq 1 && $1 == --sync-runtime-id ]]; then
	sync_only=1
elif [[ $# -ne 0 ]]; then
	echo "usage: $0 [--replace | --sync-runtime-id]" >&2
	exit 64
fi

runtime_uid=$(id -u)
runtime_gid=$(id -g)

if [[ $runtime_uid -eq 0 ]] || [[ $runtime_gid -eq 0 ]]; then
	echo "Initialize the deployment as a non-root user and group." >&2
	exit 64
fi

case "$repo_dir" in
/mnt/*)
	echo "Secrets must be stored on the WSL ext4 filesystem." >&2
	exit 64
	;;
esac

# Synchronizes the ignored Compose identity file without replacing local tuning.
#
# Side effects:
#   Atomically updates ARRAYVPN_UID and ARRAYVPN_GID in the repository .env.
sync_runtime_identity() {
	local marker='# Managed by scripts/init-secrets.sh.'
	local temporary

	if [[ -e $runtime_env ]] &&
		[[ ! -f $runtime_env || -L $runtime_env ]]; then
		echo ".env must be a regular non-symlink file." >&2
		exit 64
	fi

	if [[ -e $runtime_env ]] &&
		[[ $(stat -c '%u' "$runtime_env") -ne $runtime_uid ]]; then
		echo ".env must be owned by the invoking user." >&2
		exit 64
	fi

	temporary=$(mktemp "$repo_dir/.env.runtime.XXXXXX")

	if [[ -e $runtime_env ]]; then
		awk '!/^ARRAYVPN_(UID|GID)=/' "$runtime_env" >"$temporary"
	fi

	if [[ -s $temporary ]] && [[ -n $(tail -c 1 "$temporary") ]]; then
		printf '\n' >>"$temporary"
	fi

	if ! grep -Fqx "$marker" "$temporary"; then
		printf '%s\n' "$marker" >>"$temporary"
	fi

	printf 'ARRAYVPN_UID=%s\nARRAYVPN_GID=%s\n' \
		"$runtime_uid" "$runtime_gid" >>"$temporary"

	chmod 0600 "$temporary"
	mv -f -- "$temporary" "$runtime_env"
}

if ((sync_only)); then
	sync_runtime_identity
	echo "Synchronized non-root runtime identity in $runtime_env."
	exit 0
fi

install -d -m 700 "$secret_dir"

if ((!replace)); then
	for secret_name in vpn_username vpn_password id_card_last6 phone_missing4; do
		if [[ -e $secret_dir/$secret_name ]]; then
			echo "Secret files already exist; use --replace or --sync-runtime-id." >&2
			exit 64
		fi
	done
fi

IFS= read -r -s -p 'VPN username: ' secret_username
printf '\n'
IFS= read -r -s -p 'VPN password: ' secret_password
printf '\n'
IFS= read -r -s -p 'ID-card last 6: ' secret_id_card
printf '\n'
IFS= read -r -s -p 'Missing phone 4 digits: ' secret_phone
printf '\n'

if [[ -z $secret_username || ${#secret_username} -gt 256 ]]; then
	echo "Invalid VPN username length." >&2
	exit 64
fi

if [[ -z $secret_password || ${#secret_password} -gt 1024 ]]; then
	echo "Invalid VPN password length." >&2
	exit 64
fi

if [[ ! $secret_id_card =~ ^[0-9]{5}[0-9Xx]$ ]]; then
	echo "id_card_last6 must match [0-9]{5}[0-9Xx]." >&2
	exit 64
fi

if [[ ! $secret_phone =~ ^[0-9]{4}$ ]]; then
	echo "phone_missing4 must contain exactly four digits." >&2
	exit 64
fi

sync_runtime_identity

# Atomically replaces one secret without exposing it through argv or logs.
#
# Args:
#   $1: Fixed secret filename.
#   $2: Already validated secret value.
write_secret() {
	local name=$1 value=$2
	local temporary
	temporary=$(mktemp "$secret_dir/.${name}.XXXXXX")
	printf '%s' "$value" >"$temporary"
	chmod 0600 "$temporary"
	mv -f -- "$temporary" "$secret_dir/$name"
}

write_secret vpn_username "$secret_username"
write_secret vpn_password "$secret_password"
write_secret id_card_last6 "$secret_id_card"
write_secret phone_missing4 "$secret_phone"
unset secret_username secret_password secret_id_card secret_phone
chmod 0700 "$secret_dir"
chmod 0600 "$secret_dir"/*
echo "Created four 0600 secret files under $secret_dir."
