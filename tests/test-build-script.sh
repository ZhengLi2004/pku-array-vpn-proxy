#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests local-package validation, optional mirrors, and build delegation.
set -Eeuo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)
mkdir -p "$repo_dir/artifacts"
work_dir=$(mktemp -d "$repo_dir/artifacts/build-script-test.XXXXXX")
fake_docker=$repo_dir/tests/fake-docker.sh
fake_log=$work_dir/docker.log

# Removes only the randomized build-script test workspace.
cleanup() {
	case $work_dir in
	"$repo_dir"/artifacts/build-script-test.*) rm -rf -- "$work_dir" ;;
	esac
}

trap cleanup EXIT HUP INT TERM

# Reports a build-preflight regression and terminates the test.
fail() {
	echo "build script test failed: $*" >&2
	exit 1
}

valid_repo=$work_dir/valid-repo
mkdir -p "$valid_repo/scripts" "$valid_repo/local"
cp "$repo_dir/scripts/build.sh" "$valid_repo/scripts/"
cp "$repo_dir/versions.env" "$valid_repo/versions.env"
printf 'synthetic package fixture' >"$valid_repo/local/iSecSP_ubuntu_2.4.0.deb"

synthetic_deb_sha=$(sha256sum "$valid_repo/local/iSecSP_ubuntu_2.4.0.deb" |
	awk '{print $1}')

sed -i "s/^ISECSP_DEB_SHA256=.*/ISECSP_DEB_SHA256=$synthetic_deb_sha/" \
	"$valid_repo/versions.env"

build_script=$valid_repo/scripts/build.sh
invalid_lock_repo=$work_dir/invalid-lock-repo
cp -a "$valid_repo" "$invalid_lock_repo"

sed -i 's/^OCPROXY_COMMIT=.*/OCPROXY_COMMIT=invalid/' \
	"$invalid_lock_repo/versions.env"

if FAKE_DOCKER_LOG=$fake_log DOCKER_BIN=$fake_docker \
	"$invalid_lock_repo/scripts/build.sh" --check \
	>"$work_dir/invalid-lock.out" 2>&1; then
	fail 'an invalid ocproxy commit lock was accepted for a full build'
fi

grep -Fq 'invalid OCPROXY_COMMIT' "$work_dir/invalid-lock.out" ||
	fail 'invalid ocproxy commit failure was not explained'

# An auth-only build has no dependency on the tunnel-only ocproxy source.
FAKE_DOCKER_LOG=$fake_log DOCKER_BIN=$fake_docker \
	"$invalid_lock_repo/scripts/build.sh" --check --auth-only \
	>"$work_dir/auth-invalid-lock.out"

grep -Fq 'scope=auth' "$work_dir/auth-invalid-lock.out" ||
	fail 'auth-only preflight did not report its scope'

grep -Fq 'ocproxy_source=not-applicable' "$work_dir/auth-invalid-lock.out" ||
	fail 'auth-only preflight still depends on ocproxy'

: >"$fake_log"

FAKE_DOCKER_LOG=$fake_log DOCKER_BIN=$fake_docker \
	"$build_script" --check >"$work_dir/check.out"

for marker in \
	'scope=all' \
	'ocproxy_source=upstream-git' \
	'auth=isecsp-local' \
	'alpine_mirror=default' \
	'ubuntu_mirror=default' \
	'dockerhub_mirror=unconfigured'; do
	grep -Fq "$marker" "$work_dir/check.out" ||
		fail "default preflight did not report $marker"
done

grep -Eq 'ALPINE_MIRROR= UBUNTU_APT_MIRROR= UBUNTU_IMAGE=ubuntu:24\.04@sha256:[0-9a-f]{64} docker compose config --quiet' \
	"$fake_log" || fail 'default preflight did not export locked build inputs'

if grep -Fq ' docker info' "$fake_log"; then
	fail 'preflight unexpectedly inspected daemon registry mirrors'
fi

if grep -Fq -- '--progress plain build' "$fake_log"; then
	fail '--check unexpectedly started a build'
fi

missing_package_repo=$work_dir/missing-package-repo
cp -a "$valid_repo" "$missing_package_repo"
rm -f "$missing_package_repo/local/iSecSP_ubuntu_2.4.0.deb"

if FAKE_DOCKER_LOG=$fake_log DOCKER_BIN=$fake_docker \
	"$missing_package_repo/scripts/build.sh" --check \
	>"$work_dir/missing-package.out" 2>&1; then
	fail 'preflight accepted a missing local iSecSP package'
fi

grep -Fq 'prepare-isecsp.sh' "$work_dir/missing-package.out" ||
	fail 'missing iSecSP package failure was not explained'

wrong_package_repo=$work_dir/wrong-package-repo
cp -a "$valid_repo" "$wrong_package_repo"
printf 'changed package fixture' >"$wrong_package_repo/local/iSecSP_ubuntu_2.4.0.deb"

if FAKE_DOCKER_LOG=$fake_log DOCKER_BIN=$fake_docker \
	"$wrong_package_repo/scripts/build.sh" --check \
	>"$work_dir/wrong-package.out" 2>&1; then
	fail 'preflight accepted a package with the wrong hash'
fi

grep -Fq 'does not match versions.env' "$work_dir/wrong-package.out" ||
	fail 'package hash failure was not explained'

proxy_repo=$work_dir/proxy-repo
cp -a "$valid_repo" "$proxy_repo"

cat >"$proxy_repo/proxy.env" <<'EOF'
ALPINE_MIRROR=https://mirror.example/alpine/
UBUNTU_APT_MIRROR=https://mirror.example/ubuntu/
UBUNTU_IMAGE=registry.example/ubuntu:24.04@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
DOCKERHUB_MIRROR=https://registry.example/
EOF

: >"$fake_log"

FAKE_DOCKER_LOG=$fake_log DOCKER_BIN=$fake_docker \
	"$proxy_repo/scripts/build.sh" --check >"$work_dir/proxy-file.out"

for marker in \
	'alpine_mirror=https://mirror.example/alpine' \
	'ubuntu_mirror=https://mirror.example/ubuntu' \
	'dockerhub_mirror=recorded'; do
	grep -Fq "$marker" "$work_dir/proxy-file.out" ||
		fail "proxy.env did not report $marker"
done

grep -Fq \
	'ALPINE_MIRROR=https://mirror.example/alpine UBUNTU_APT_MIRROR=https://mirror.example/ubuntu UBUNTU_IMAGE=registry.example/ubuntu:24.04@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa docker compose config --quiet' \
	"$fake_log" || fail 'proxy.env values were not passed to Compose'

printf '%s\n' 'UNSUPPORTED_MIRROR=https://mirror.example' \
	>"$proxy_repo/proxy.env"

if FAKE_DOCKER_LOG=$fake_log DOCKER_BIN=$fake_docker \
	"$proxy_repo/scripts/build.sh" --check \
	>"$work_dir/invalid-proxy-file.out" 2>&1; then
	fail 'an unsupported proxy.env key was accepted'
fi

grep -Fq 'unsupported key' "$work_dir/invalid-proxy-file.out" ||
	fail 'the unsupported proxy.env key failure was not explained'

invalid_mirror_index=0

for invalid_mirror in \
	http://mirror.example/alpine \
	https://user@mirror.example/alpine \
	'https://mirror.example/alpine?channel=test'; do
	invalid_mirror_index=$((invalid_mirror_index + 1))

	if ALPINE_MIRROR=$invalid_mirror FAKE_DOCKER_LOG=$fake_log \
		DOCKER_BIN=$fake_docker "$build_script" --check \
		>"$work_dir/invalid-mirror-$invalid_mirror_index.out" 2>&1; then
		fail "invalid optional mirror was accepted: $invalid_mirror_index"
	fi

	grep -Fq 'ALPINE_MIRROR' \
		"$work_dir/invalid-mirror-$invalid_mirror_index.out" ||
		fail "invalid mirror failure was not explained: $invalid_mirror_index"
done

: >"$fake_log"

FAKE_DOCKER_LOG=$fake_log DOCKER_BIN=$fake_docker \
	"$build_script" >"$work_dir/build.out"

grep -Fq 'compose --progress plain build' "$fake_log" ||
	fail 'full mode did not delegate to Compose build'

if grep -Fq 'compose --progress plain build array-auth' "$fake_log"; then
	fail 'full mode unexpectedly selected only array-auth'
fi

: >"$fake_log"

FAKE_DOCKER_LOG=$fake_log DOCKER_BIN=$fake_docker \
	"$build_script" --auth-only >"$work_dir/auth-build.out"

grep -Fq 'compose --progress plain build array-auth' "$fake_log" ||
	fail 'auth-only mode did not select just array-auth'

# Requires one invalid argument sequence to be rejected.
#
# Args:
#   $1: Diagnostic label for the invalid case.
#   $2...: Arguments passed to the build script.
assert_invalid() {
	local label=$1
	shift

	if FAKE_DOCKER_LOG=$fake_log DOCKER_BIN=$fake_docker \
		"$build_script" "$@" >"$work_dir/invalid.out" 2>&1; then
		fail "invalid arguments were accepted: $label"
	fi
}

assert_invalid duplicate-check --check --check
assert_invalid duplicate-scope --auth-only --auth-only
assert_invalid removed-backend --isecsp
assert_invalid unknown --unknown
echo 'build_script_test=ok'
