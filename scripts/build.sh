#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Validates portable build inputs and delegates explicitly requested Docker builds.
set -Eeuo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)
docker_bin=${DOCKER_BIN:-docker}
proxy_file=$repo_dir/proxy.env
mode=build
scope=all

# Prints the supported build and validation command-line interface.
usage() {
	cat <<'EOF'
Usage: ./scripts/build.sh [--check] [--auth-only]

Without arguments, build the tunnel image and local iSecSP authentication sidecar.
Docker daemon registry-mirror configuration is optional and remains outside this
project. An optional proxy.env can override Alpine and Ubuntu package repositories
and record a daemon-owned Docker Hub mirror; process environment values take priority.

--check  Validate optional build inputs and Compose without starting a build.
--auth-only  Build only the array-auth service after the same preflight.
EOF
}

# Reports one sanitized preflight failure and exits.
fail() {
	printf 'build preflight failed: %s\n' "$*" >&2
	exit 1
}

# Loads optional repository, image, and daemon-mirror build settings.
#
# Args:
#   $1: Regular non-symlink configuration path.
#
# Side effects:
#   Sets otherwise-unset mirror or Ubuntu image shell variables.
load_proxy_file() {
	local path=$1 line key value
	local -A seen=()
	[[ ! -e $path ]] && return
	[[ -f $path && ! -L $path ]] || fail 'proxy.env must be a regular file'

	while IFS= read -r line || [[ -n $line ]]; do
		line=${line%$'\r'}

		case $line in
		'' | '#'*) continue ;;
		*=*)
			key=${line%%=*}
			value=${line#*=}
			;;
		*) fail 'proxy.env contains a malformed line' ;;
		esac

		[[ ! -v seen[$key] ]] || fail "proxy.env repeats $key"
		seen[$key]=1

		case $key in
		ALPINE_MIRROR)
			[[ -v ALPINE_MIRROR ]] || ALPINE_MIRROR=$value
			;;
		UBUNTU_APT_MIRROR)
			[[ -v UBUNTU_APT_MIRROR ]] || UBUNTU_APT_MIRROR=$value
			;;
		UBUNTU_IMAGE)
			[[ -v UBUNTU_IMAGE ]] || UBUNTU_IMAGE=$value
			;;
		DOCKERHUB_MIRROR)
			[[ -v DOCKERHUB_MIRROR ]] || DOCKERHUB_MIRROR=$value
			;;
		*) fail "proxy.env contains unsupported key: $key" ;;
		esac
	done <"$path"
}

# Validates a digest-pinned OCI image reference without credentials.
validate_image() {
	local name=$1 value=$2

	[[ $value =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] ||
		fail "$name must be a digest-pinned image reference"

	[[ $value != *'@'*'@'* && $value != *'?'* && $value != *'#'* ]] ||
		fail "$name contains credentials, a query, or a fragment"
}

# Validates an optional credential-free HTTPS mirror URL.
#
# Args:
#   $1: Environment variable name used in diagnostics.
#   $2: Candidate URL; an empty value is allowed.
validate_mirror() {
	local name=$1 value=$2
	[[ -z $value ]] && return

	case $value in
	https://*) ;;
	*) fail "$name must be an HTTPS URL" ;;
	esac

	case $value in
	*[[:space:]]* | *'#'* | *'@'* | *'?'*)
		fail "$name contains whitespace, credentials, a fragment, or a query"
		;;
	esac
}

while [[ $# -gt 0 ]]; do
	case $1 in
	--check)
		[[ $mode == build ]] || fail 'duplicate --check'
		mode=check
		;;
	--auth-only)
		[[ $scope == all ]] || fail 'duplicate --auth-only'
		scope=auth
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		usage >&2
		exit 2
		;;
	esac

	shift
done

cd "$repo_dir"
load_proxy_file "$proxy_file"

[[ -x $docker_bin ]] || command -v "$docker_bin" >/dev/null 2>&1 ||
	fail "Docker CLI not found: $docker_bin"

if [[ $scope == all ]]; then
	ocproxy_commit=$(sed -n 's/^OCPROXY_COMMIT=//p' versions.env)
	ocproxy_patch_sha=$(sed -n 's/^OCPROXY_PERFORMANCE_PATCH_SHA256=//p' versions.env)
	ocproxy_patch=$repo_dir/patches/ocproxy-upload-performance.patch

	[[ $ocproxy_commit =~ ^[0-9a-f]{40}$ ]] ||
		fail 'versions.env has an invalid OCPROXY_COMMIT'

	[[ $ocproxy_patch_sha =~ ^[0-9a-f]{64}$ ]] ||
		fail 'versions.env has an invalid OCPROXY_PERFORMANCE_PATCH_SHA256'

	[[ -f $ocproxy_patch && ! -L $ocproxy_patch ]] ||
		fail 'the locked ocproxy performance patch is missing or is a symlink'

	[[ $(sha256sum "$ocproxy_patch" | awk '{print $1}') == "$ocproxy_patch_sha" ]] ||
		fail 'the ocproxy performance patch does not match versions.env'

	ocproxy_source=upstream-git+locked-performance-patch
else
	ocproxy_source=not-applicable
fi

alpine_mirror=${ALPINE_MIRROR:-}
ubuntu_apt_mirror=${UBUNTU_APT_MIRROR:-}
dockerhub_mirror=${DOCKERHUB_MIRROR:-}
validate_mirror ALPINE_MIRROR "$alpine_mirror"
validate_mirror UBUNTU_APT_MIRROR "$ubuntu_apt_mirror"
validate_mirror DOCKERHUB_MIRROR "$dockerhub_mirror"

if [[ -n $alpine_mirror ]]; then
	alpine_mirror=${alpine_mirror%/}
fi

if [[ -n $ubuntu_apt_mirror ]]; then
	ubuntu_apt_mirror=${ubuntu_apt_mirror%/}
fi

if [[ -n $dockerhub_mirror ]]; then
	dockerhub_mirror=${dockerhub_mirror%/}
	dockerhub_mirror_state=recorded
else
	dockerhub_mirror_state=unconfigured
fi

runtime_uid=${ARRAYVPN_UID:-$(id -u)}
runtime_gid=${ARRAYVPN_GID:-$(id -g)}

[[ $runtime_uid =~ ^[1-9][0-9]*$ ]] ||
	fail 'ARRAYVPN_UID must identify a non-root numeric user'

[[ $runtime_gid =~ ^[1-9][0-9]*$ ]] ||
	fail 'ARRAYVPN_GID must identify a non-root numeric group'

export ARRAYVPN_UID=$runtime_uid
export ARRAYVPN_GID=$runtime_gid
export ALPINE_MIRROR=$alpine_mirror
export PKU_ARRAY_VPN_IMAGE=pku-array-vpn-proxy:local
ubuntu_image=${UBUNTU_IMAGE:-$(sed -n 's/^UBUNTU_IMAGE=//p' versions.env)}
expected_deb_sha=$(sed -n 's/^ISECSP_DEB_SHA256=//p' versions.env)
isecsp_package=$repo_dir/local/iSecSP_ubuntu_2.4.0.deb
validate_image UBUNTU_IMAGE "$ubuntu_image"

[[ -f $isecsp_package && ! -L $isecsp_package ]] ||
	fail 'run ./scripts/prepare-isecsp.sh with the official package first'

[[ $(sha256sum "$isecsp_package" | awk '{print $1}') == "$expected_deb_sha" ]] ||
	fail 'the staged iSecSP package does not match versions.env'

export UBUNTU_IMAGE=$ubuntu_image
export UBUNTU_APT_MIRROR=$ubuntu_apt_mirror
"$docker_bin" compose config --quiet

printf 'build_preflight=ok scope=%s alpine_mirror=%s ubuntu_mirror=%s dockerhub_mirror=%s ocproxy_source=%s auth=%s\n' \
	"$scope" "${alpine_mirror:-default}" "${ubuntu_apt_mirror:-default}" \
	"$dockerhub_mirror_state" "$ocproxy_source" 'isecsp-local'

if [[ $mode == check ]]; then
	exit 0
fi

if [[ $scope == auth ]]; then
	exec "$docker_bin" compose --progress plain build array-auth
fi

exec "$docker_bin" compose --progress plain build
