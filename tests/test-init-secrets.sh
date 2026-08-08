#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests private secret creation, validation, permissions, and replacement.
set -Eeuo pipefail
source_script=${1:-scripts/init-secrets.sh}
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
install -d -m 0700 "$repo_dir/artifacts"
test_root=$(mktemp -d "$repo_dir/artifacts/.init-secrets-test.XXXXXX")

# Removes only the randomized secret-initialization fixture directory.
cleanup() {
	case "$test_root" in
	"$repo_dir"/artifacts/.init-secrets-test.*) rm -rf -- "$test_root" ;;
	*) echo 'refusing unsafe test cleanup' >&2 ;;
	esac
}

trap cleanup EXIT HUP INT TERM
install -d -m 0700 "$test_root/repo/scripts"
cp -- "$source_script" "$test_root/repo/scripts/init-secrets.sh"
chmod 0755 "$test_root/repo/scripts/init-secrets.sh"

printf 'alice\ncorrect horse battery staple\n12345X\n6789\n' |
	"$test_root/repo/scripts/init-secrets.sh" >/dev/null 2>&1

test "$(stat -c '%u:%g:%a' "$test_root/repo/.env")" = \
	"$(id -u):$(id -g):600"

test "$(grep -Fxc "ARRAYVPN_UID=$(id -u)" "$test_root/repo/.env")" -eq 1
test "$(grep -Fxc "ARRAYVPN_GID=$(id -g)" "$test_root/repo/.env")" -eq 1

for name in vpn_username vpn_password id_card_last6 phone_missing4; do
	test "$(stat -c '%u:%g:%a' "$test_root/repo/secrets/$name")" = \
		"$(id -u):$(id -g):600"

	if od -An -t u1 "$test_root/repo/secrets/$name" |
		awk '{ for (i = 1; i <= NF; i++) if ($i == 10 || $i == 13) bad = 1 }
		     END { exit bad ? 0 : 1 }'; then
		echo "$name contains a newline" >&2
		exit 1
	fi
done

test "$(cat "$test_root/repo/secrets/vpn_username")" = alice
test "$(cat "$test_root/repo/secrets/id_card_last6")" = 12345X
test "$(cat "$test_root/repo/secrets/phone_missing4")" = 6789
printf '%s\n' 'HEALTHCHECK_INTERVAL=90' >>"$test_root/repo/.env"
"$test_root/repo/scripts/init-secrets.sh" --sync-runtime-id >/dev/null
grep -Fqx 'HEALTHCHECK_INTERVAL=90' "$test_root/repo/.env"
test "$(grep -Fxc "ARRAYVPN_UID=$(id -u)" "$test_root/repo/.env")" -eq 1
test "$(grep -Fxc "ARRAYVPN_GID=$(id -g)" "$test_root/repo/.env")" -eq 1

if "$test_root/repo/scripts/init-secrets.sh" </dev/null >/dev/null 2>&1; then
	echo 'existing secrets were overwritten without --replace' >&2
	exit 1
fi

if "$test_root/repo/scripts/init-secrets.sh" --replace extra \
	</dev/null >/dev/null 2>&1; then
	echo 'extra arguments were accepted' >&2
	exit 1
fi

if printf 'bob\nnew password\ninvalid\n1234\n' |
	"$test_root/repo/scripts/init-secrets.sh" --replace \
		>/dev/null 2>&1; then
	echo 'invalid ID-card secret was accepted' >&2
	exit 1
fi

test "$(cat "$test_root/repo/secrets/vpn_username")" = alice
echo 'init_secrets_test=ok'
