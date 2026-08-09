#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs offline source, security, protocol, and authentication regression checks.
set -Eeuo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)

# Reports one static-contract violation and terminates the check suite.
fail() {
	printf 'static check failed: %s\n' "$*" >&2
	exit 1
}

# Requires one file to contain an exact complete line.
require_line() {
	local file=$1 line=$2 message=$3
	grep -Fqx -- "$line" "$file" || fail "$message"
}

# Requires one file to contain an exact fixed substring.
require_text() {
	local file=$1 text=$2 message=$3
	grep -Fq -- "$text" "$file" || fail "$message"
}

cd "$repo_dir"

require_line .gitattributes 'patches/*.patch text eol=lf -whitespace' \
	'ocproxy patch bytes must remain stable across host line-ending settings'

for source_file in scripts/*.sh scripts/*.py scripts/*.exp \
	tests/*.sh tests/*.py Dockerfile Dockerfile.isecsp-auth \
	Dockerfile.isecsp-auth.dockerignore Makefile src/isecsp-auth/Makefile \
	compose.yaml .env.example proxy.env.example versions.env \
	.github/workflows/*.yaml; do
	require_line "$source_file" '# SPDX-License-Identifier: Apache-2.0' \
		"$source_file lacks an Apache-2.0 SPDX identifier"
done

for source_file in src/auth-ipc/*.c src/auth-ipc/*.h \
	src/isecsp-auth/*.c src/isecsp-auth/*.h tests/*.c; do
	require_line "$source_file" '/* SPDX-License-Identifier: Apache-2.0 */' \
		"$source_file lacks an Apache-2.0 SPDX identifier"
done

for script in scripts/*.sh tests/*.sh; do
	bash -n "$script"
	[[ -x $script ]] || fail "$script is not executable"
done

for executable in scripts/openconnect-driver.exp scripts/check-socks-target.py; do
	[[ -x $executable ]] || fail "$executable is not executable"
done

if grep -nE 'mktemp[^[:cntrl:]]*[[:space:]]/tmp/' tests/*.sh; then
	fail 'host tests must keep temporary state under the repository artifacts directory'
fi

python3 -c 'compile(open("scripts/check-socks-target.py", encoding="utf-8").read(), "scripts/check-socks-target.py", "exec")'
python3 tests/test-check-socks-target.py
tests/test-healthcheck.sh
tests/test-init-secrets.sh
tests/test-resolver.sh
tests/test-build-script.sh
tests/test-isecsp-auth-helper.sh
git diff --check
git diff --cached --check

for private_path in secrets/vpn_username proxy.env \
	local/iSecSP_ubuntu_2.4.0.deb; do
	git check-ignore -q "$private_path" ||
		fail "$private_path is not ignored by Git"

	if git ls-files --error-unmatch "$private_path" >/dev/null 2>&1; then
		fail "$private_path is tracked by Git"
	fi
done

set +e

git grep -I -q -E \
	-e '-----BEGIN[[:space:]]+([A-Z0-9]+[[:space:]]+)?PRIVATE[[:space:]]+KEY-----' \
	-e 'AKIA[0-9A-Z]{16}' \
	-e 'gh[pousr]_[A-Za-z0-9]{36,255}' \
	-e 'xox[baprs]-[A-Za-z0-9-]{10,}' \
	-- .

secret_scan_status=$?
set -e

case $secret_scan_status in
0) fail 'the tracked worktree contains a common private-key or token signature' ;;
1) ;;
*) fail 'unable to scan the tracked worktree for common secret signatures' ;;
esac

for license_file in LICENSE NOTICE THIRD_PARTY_NOTICES.md; do
	[[ -f $license_file && ! -L $license_file ]] ||
		fail "$license_file is missing or is a symlink"
done

require_line LICENSE '                                 Apache License' \
	'project license is not Apache-2.0'

require_line LICENSE '                           Version 2.0, January 2004' \
	'project license version is wrong'

require_line NOTICE 'Copyright 2026 ZhengLi2004 and contributors' \
	'project copyright notice is missing'

for marker in 'LGPL-2.1-only' 'BSD-3-Clause' \
	'c98f06d942970cdf35dd66ab46840f7d6d567b60' \
	'patches/ocproxy-upload-performance.patch' \
	'beab1230018ac3fc3c9635a060b5c251a4c3707eee51c94425c309a1ed1232bf' \
	'Local-only iSecSP authentication backend'; do
	require_text THIRD_PARTY_NOTICES.md "$marker" \
		"third-party notice lacks $marker"
done

mapfile -t documentation_files < <(
	find docs -type f -printf '%P\n' | LC_ALL=C sort
)

[[ ${#documentation_files[@]} -eq 2 &&
	${documentation_files[0]} == ARCHITECTURE.md &&
	${documentation_files[1]} == AUTH_PROTOCOL.md ]] ||
	fail 'docs must contain only system architecture and interface protocol'

require_line docs/ARCHITECTURE.md '# 系统架构' \
	'architecture document has the wrong contract'

require_line docs/AUTH_PROTOCOL.md '# 接口与认证协议' \
	'interface protocol document has the wrong contract'

require_line config/servercert-pins.txt \
	'pin-sha256:2KFOU2AGwT7NAeqN83knLoeX5Nd0yGgB7cc6XQTmNhk=' \
	'the initial PKU SPKI pin is missing'

[[ $(wc -l <config/servercert-pins.txt) -eq 1 ]] ||
	fail 'the default pin file must contain exactly one pin'

for lock in \
	'DOCKERFILE_FRONTEND_IMAGE=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e' \
	'OPENCONNECT_COMMIT=8b702bf2dbaf11302ed98629214b1df5d50a12aa' \
	'OCPROXY_COMMIT=c98f06d942970cdf35dd66ab46840f7d6d567b60' \
	'OCPROXY_PERFORMANCE_PATCH_SHA256=beab1230018ac3fc3c9635a060b5c251a4c3707eee51c94425c309a1ed1232bf' \
	'ALPINE_IMAGE=alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b' \
	'UBUNTU_IMAGE=ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea' \
	'ISECSP_DEB_SHA256=4b062dfa4a9a89cbb60d538b1cc3cb47d014ff91e907db16c891fcd9ebd91d6c' \
	'ISECSP_LIBRARY_SHA256=0a20b9f9760c845e805fdbdded968100344c2cc3026ef1134dd81ae664135787' \
	'ISEC_LIBRARY_SHA256=cf9df4e6726d95c2f06d38efe5a07684520c90300b147e8915a6c130d7c9469e' \
	'JQ_APK_VERSION=1.8.2-r0'; do
	require_line versions.env "$lock" "versions.env lacks lock: $lock"
done

if grep -Eq '(^|_)(MIRROR|REPOSITORY)=' versions.env; then
	fail 'deployment-specific repository settings do not belong in version locks'
fi

ocproxy_commit=$(sed -n 's/^OCPROXY_COMMIT=//p' versions.env)
ocproxy_patch_sha=$(sed -n 's/^OCPROXY_PERFORMANCE_PATCH_SHA256=//p' versions.env)
ocproxy_patch=patches/ocproxy-upload-performance.patch

[[ $ocproxy_commit =~ ^[0-9a-f]{40}$ ]] ||
	fail 'ocproxy commit lock is malformed'

[[ $ocproxy_patch_sha =~ ^[0-9a-f]{64}$ ]] ||
	fail 'ocproxy performance patch lock is malformed'

[[ -f $ocproxy_patch && ! -L $ocproxy_patch ]] ||
	fail 'ocproxy performance patch is missing or is a symlink'

git check-ignore -q "$ocproxy_patch" &&
	fail 'ocproxy performance patch is excluded from source control'

git ls-files --error-unmatch "$ocproxy_patch" >/dev/null 2>&1 ||
	fail 'ocproxy performance patch is not tracked by Git'

[[ $(sha256sum "$ocproxy_patch" | awk '{print $1}') == "$ocproxy_patch_sha" ]] ||
	fail 'ocproxy performance patch does not match versions.env'

mapfile -t ocproxy_patch_targets < <(
	git apply --numstat -- "$ocproxy_patch" | awk '{print $3}' | LC_ALL=C sort
)

[[ ${#ocproxy_patch_targets[@]} -eq 2 &&
	${ocproxy_patch_targets[0]} == src/lwipopts.h &&
	${ocproxy_patch_targets[1]} == src/ocproxy.c ]] ||
	fail 'ocproxy performance patch modifies an unexpected path'

for marker in \
	'#define MEM_SIZE                (4U * 1024U * 1024U)' \
	'#define LWIP_WND_SCALE          1' \
	'#define TCP_RCV_SCALE           0' \
	'#define TCP_MSS                 1024' \
	'#define TCP_SND_BUF             (256U * 1024U)' \
	'VPN_QUEUE_MAX_BYTES' \
	'O_NONBLOCK' \
	'EV_WRITE' \
	'vpn_set_backpressure' \
	'VPN output queue overflow'; do
	require_text "$ocproxy_patch" "$marker" \
		"ocproxy performance patch lacks $marker"
done

if grep -Eq '^[+-]#define (TCP_MSS|TCP_WND)[[:space:]]' "$ocproxy_patch"; then
	fail 'the first performance patch must preserve ocproxy TCP_MSS and TCP_WND'
fi

for marker in \
	"ARG OCPROXY_COMMIT=$ocproxy_commit" \
	"ARG OCPROXY_PERFORMANCE_PATCH_SHA256=$ocproxy_patch_sha" \
	"test \"\$OCPROXY_PERFORMANCE_PATCH_SHA256\" = \"$ocproxy_patch_sha\"" \
	'git remote add origin https://github.com/cernekee/ocproxy.git' \
	'git -c http.version=HTTP/1.1 fetch --depth=1 --no-tags' \
	'test "$(git rev-parse HEAD)" = "$OCPROXY_COMMIT"' \
	'COPY patches/ocproxy-upload-performance.patch /build/patches/ocproxy-upload-performance.patch' \
	'sha256sum -c -' \
	'git -C /build/ocproxy apply --check --whitespace=error-all' \
	'git -C /build/ocproxy apply --whitespace=error-all' \
	'git -C /build/ocproxy diff --check' \
	'--with-gnutls' \
	'--without-openssl' \
	'src/auth-ipc/client.c' \
	'/usr/local/bin/array-auth-client'; do
	require_text Dockerfile "$marker" "tunnel Dockerfile lacks $marker"
done

[[ ! -e vendor ]] || fail 'ocproxy source must not be vendored in the repository'
frontend_image=$(sed -n 's/^DOCKERFILE_FRONTEND_IMAGE=//p' versions.env)
frontend="# syntax=$frontend_image"
require_line Dockerfile "$frontend" 'tunnel Dockerfile frontend is not pinned'

require_line Dockerfile.isecsp-auth "$frontend" \
	'authentication Dockerfile frontend is not pinned'

require_line Dockerfile 'USER arrayvpn:arrayvpn' \
	'tunnel image does not use its named non-root identity'

require_line Dockerfile.isecsp-auth 'USER arrayvpn:arrayvpn' \
	'authentication image does not use its named non-root identity'

for marker in \
	'ARG UBUNTU_IMAGE=ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea' \
	'ARG UBUNTU_APT_MIRROR' \
	'ISECSP_DEB_SHA256=4b062dfa4a9a89cbb60d538b1cc3cb47d014ff91e907db16c891fcd9ebd91d6c' \
	'ISECSP_LIBRARY_SHA256=0a20b9f9760c845e805fdbdded968100344c2cc3026ef1134dd81ae664135787' \
	'ISEC_LIBRARY_SHA256=cf9df4e6726d95c2f06d38efe5a07684520c90300b147e8915a6c130d7c9469e' \
	'--mount=type=bind,source=local/iSecSP_ubuntu_2.4.0.deb' \
	'dpkg-deb -x /build/isecsp.deb' \
	'LABEL org.opencontainers.image.licenses="Apache-2.0 AND LicenseRef-iSecSP-Proprietary"' \
	'/opt/isecsp/libvl3vpn.so' \
	'/opt/isecsp/libisec.so'; do
	require_text Dockerfile.isecsp-auth "$marker" \
		"authentication Dockerfile lacks $marker"
done

if grep -Eq 'dpkg(-deb)?[[:space:]]+(-i|--install)|postinst|isecspdaemon|vpn_cmdline' \
	Dockerfile.isecsp-auth; then
	fail 'authentication image installs or runs the official client package'
fi

for license_path in \
	'/usr/share/licenses/openconnect/COPYING.LGPL' \
	'/usr/share/licenses/ocproxy/LICENSE' \
	'/usr/share/licenses/ocproxy/AUTHORS' \
	'/usr/share/licenses/lwip/COPYING' \
	'/usr/share/licenses/pku-array-vpn-proxy/'; do
	require_text Dockerfile "$license_path" \
		"tunnel image does not retain $license_path"
done

for excluded_path in secrets artifacts local captures logs; do
	require_line .dockerignore "$excluded_path" \
		"Docker build context does not exclude $excluded_path"
done

require_line .dockerignore 'proxy.env' \
	'local proxy configuration is included in the Docker build context'

for marker in \
	'array-auth:' \
	'dockerfile: Dockerfile.isecsp-auth' \
	'${PKU_ARRAY_VPN_IMAGE:-pku-array-vpn-proxy:local}' \
	'VPN_DATA_TRANSPORT: ${VPN_DATA_TRANSPORT:-tls}' \
	'pku-array-vpn-auth:isecsp-local' \
	'UBUNTU_APT_MIRROR: ${UBUNTU_APT_MIRROR:-}' \
	'${ARRAYVPN_UID:?run ./scripts/init-secrets.sh}' \
	'${ARRAYVPN_GID:?run ./scripts/init-secrets.sh}' \
	'restart: true' \
	'/run/isecsp:rw,nosuid,nodev,noexec' \
	'/usr/local/bin/isecsp-auth-client'; do
	require_text compose.yaml "$marker" "Compose lacks $marker"
done

if grep -RInE '/dev/net/tun|NET_ADMIN|network_mode:[[:space:]]*host|privileged:[[:space:]]*true' \
	Dockerfile Dockerfile.isecsp-auth compose.yaml src/isecsp-auth; then
	fail 'runtime configuration can modify a TUN or host network'
fi

if git grep -n -i -E \
	'1000:1000|(^|[^[:alnum:]_])([[:alnum:]_]+_)?(uid|gid)[=:][[:space:]]*1000([^0-9]|$)|(^|[[:space:]])(--(uid|gid)|-[ug])[=[:space:]]+1000([^0-9]|$)' \
	-- . ':!scripts/check-static.sh'; then
	fail 'a fixed runtime UID/GID remains in tracked project code'
fi

for marker in \
	'load_proxy_file "$proxy_file"' \
	'alpine_mirror=${ALPINE_MIRROR:-}' \
	'ubuntu_image=${UBUNTU_IMAGE:-$(sed' \
	'local/iSecSP_ubuntu_2.4.0.deb' \
	'export PKU_ARRAY_VPN_IMAGE=pku-array-vpn-proxy:local' \
	'--auth-only' \
	'build array-auth'; do
	require_text scripts/build.sh "$marker" "build entry point lacks $marker"
done

if grep -Fq '"$docker_bin" info' scripts/build.sh; then
	fail 'build entry point still inspects daemon registry mirrors'
fi

if grep -Fq -- '--isecsp' scripts/build.sh Makefile README.md; then
	fail 'removed backend-selection interface remains'
fi

for marker in \
	'sync_runtime_identity' \
	'ARRAYVPN_UID=%s' \
	'ARRAYVPN_GID=%s' \
	'--sync-runtime-id'; do
	require_text scripts/init-secrets.sh "$marker" \
		"runtime identity initialization lacks $marker"
done

require_text scripts/entrypoint.sh '[[ $(id -g) -eq 0 ]]' \
	'tunnel runtime does not reject a root group'

require_text src/isecsp-auth/server.c 'if (geteuid() == 0 || getegid() == 0)' \
	'authentication runtime does not reject a root identity'

require_text scripts/entrypoint.sh 'auth_cache_needs_invalidation' \
	'supervisor does not invalidate completed auth sessions'

require_text scripts/entrypoint.sh '/usr/local/bin/array-auth-client --invalidate' \
	'supervisor uses the wrong auth client'

jq_sha=$(sed -n 's/^JQ_APK_SHA256=//p' versions.env)

require_text Dockerfile "ARG JQ_APK_SHA256=$jq_sha" \
	'Dockerfile does not verify the locked jq APK'

if grep -Eq '^OPENCONNECT_.*PATCH' versions.env ||
	sed -n '/RUN git init openconnect/,/^COPY patches\/ocproxy-upload-performance\.patch/p' \
		Dockerfile | grep -Eq 'git([[:space:]]+-C[[:space:]]+[^[:space:]]+)?[[:space:]]+apply|(^|&&[[:space:]]+)patch[[:space:]]'; then
	fail 'OpenConnect must be built from the unmodified locked upstream commit'
fi

[[ $(grep -Ec 'git -C /build/ocproxy apply( --check)? --whitespace=error-all' \
	Dockerfile) -eq 2 ]] ||
	fail 'Dockerfile must apply only the locked ocproxy performance patch'

[[ $(grep -Ec 'git([[:space:]]+-C[[:space:]]+[^[:space:]]+)?[[:space:]]+apply([[:space:]]|$)' \
	Dockerfile) -eq 2 ]] ||
	fail 'Dockerfile contains an additional source patch operation'

require_text Dockerfile \
	$'git -C /build/ocproxy apply --check --whitespace=error-all \\\n     /build/patches/ocproxy-upload-performance.patch' \
	'Dockerfile checks the wrong ocproxy performance patch'

require_text Dockerfile \
	$'git -C /build/ocproxy apply --whitespace=error-all \\\n     /build/patches/ocproxy-upload-performance.patch' \
	'Dockerfile applies the wrong ocproxy performance patch'

[[ $(grep -Fc 'COPY patches/' Dockerfile) -eq 1 ]] ||
	fail 'Dockerfile must copy only the locked ocproxy performance patch'

if grep -Eq '(^|&&[[:space:]]+)patch[[:space:]]' Dockerfile; then
	fail 'Dockerfile contains an unreviewed patch command'
fi

[[ $(head -n 1 scripts/openconnect-driver.exp) == '#!/usr/bin/expect -f' ]] ||
	fail 'OpenConnect driver must start with an exact Expect shebang'

for driver_marker in \
	'^ANsession[A-Za-z0-9_.-]*=[^\x00-\x20\x7f;]+$' \
	'--protocol=array' \
	'--resolve=[format "%s:%s" $array_host $candidate]' \
	'set data_transport "tls"' \
	'env(VPN_DATA_TRANSPORT)' \
	'{^(auto|tls)$}' \
	'if {$data_transport eq "tls"}' \
	'lappend command --no-dtls' \
	'DRIVER_TRANSPORT_INVALID' \
	'lappend command --servercert=$pin' \
	'%UNSAFE_RENEGOTIATION:-3DES-CBC:-ARCFOUR-128' \
	'--cookie-on-stdin' \
	'--non-inter' \
	'array-auth-client'; do
	require_text scripts/openconnect-driver.exp "$driver_marker" \
		"OpenConnect driver lacks $driver_marker"
done

require_line .env.example 'VPN_DATA_TRANSPORT=tls' \
	'.env.example must preserve the TLS-only data transport default'

if grep -Fq -- '--cookie=' scripts/openconnect-driver.exp; then
	fail 'session cookies must not appear in the OpenConnect argument vector'
fi

for gateway_script in scripts/entrypoint.sh scripts/openconnect-driver.exp \
	scripts/resolve-array.sh scripts/verify-gateway-pin.sh \
	scripts/inspect-certificates.sh; do
	require_text "$gateway_script" 'arrayvpn.pku.edu.cn' \
		"fixed PKU gateway is missing from $gateway_script"
done

if grep -Fq 'ARRAY_HOST' .env.example compose.yaml; then
	fail 'the fixed PKU gateway must not be a runtime setting'
fi

if grep -RIn --exclude=check-static.sh -- '--allow-insecure-crypto' \
	Dockerfile scripts; then
	fail 'broad insecure-crypto mode is forbidden'
fi

for obsolete_path in \
	Dockerfile.native-auth compose.isecsp.yaml config/openssl-array-client.cnf \
	src/native-auth scripts/array-auth-once.sh tests/fake-native-array-server.py \
	tests/test-native-auth.c tests/test-native-auth.sh \
	tests/test-native-auth-flow.sh tests/test-native-auth-server.sh \
	tests/test-native-session.c tests/test-native-session.sh; do
	[[ ! -e $obsolete_path ]] || fail "obsolete implementation remains: $obsolete_path"
done

require_line Makefile \
	'post-build-check: test build-check inspect-runtime build-manifest' \
	'post-build-check must inspect without triggering a build'

if sed -n '/^post-build-check:/,/^[^[:space:]#]/p' Makefile |
	grep -Eq '(^|[[:space:]])build($|[[:space:]])'; then
	fail 'post-build-check unexpectedly triggers a Docker build'
fi

release_workflow=.github/workflows/release-images.yaml

for marker in \
	'platforms: linux/amd64' \
	'ghcr.io/zhengli2004/pku-array-vpn-proxy' \
	'packages: write' \
	'attestations: write' \
	'id-token: write' \
	'sbom: true' \
	'provenance: mode=max' \
	'push-to-registry: true' \
	'if [[ ! $GITHUB_REF_NAME =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]' \
	'git merge-base --is-ancestor "$GITHUB_SHA" origin/main' \
	'actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803' \
	'docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f' \
	'docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9' \
	'docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8' \
	'actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6'; do
	require_text "$release_workflow" "$marker" \
		"release workflow lacks $marker"
done

if grep -niE 'isecsp|libvl3vpn|libisec\.so|pku-array-vpn-auth|Dockerfile\.isecsp-auth' \
	"$release_workflow"; then
	fail 'release workflow must not build or publish the local authentication image'
fi

if grep -Eq '^[[:space:]]*uses:[[:space:]].*@(v[0-9]+|main|master)([[:space:]]|$)' \
	"$release_workflow"; then
	fail 'release workflow actions must be pinned to full commits'
fi

if grep -Eq '(^|:)latest([[:space:]]|$)' "$release_workflow"; then
	fail 'release workflow must not publish a mutable latest tag'
fi

if grep -E 'secrets\.[A-Za-z_][A-Za-z0-9_]*' "$release_workflow" |
	grep -Fv 'secrets.GITHUB_TOKEN'; then
	fail 'release workflow references a secret other than GITHUB_TOKEN'
fi

require_line Makefile '	docker compose down --remove-orphans' \
	'clean-runtime must remove orphan containers'

printf 'static_checks=ok auth=isecsp-local\n'
