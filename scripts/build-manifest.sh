#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Records reproducible source, package, and binary metadata for built images.
set -Eeuo pipefail
umask 077
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)
compose_files=(-f compose.yaml)

[[ $# -eq 0 ]] || {
	printf 'usage: build-manifest.sh\n' >&2
	exit 64
}

image=${IMAGE:-}
auth_image=${AUTH_IMAGE:-}
artifact_dir=$repo_dir/artifacts
manifest=$artifact_dir/build-manifest.txt
temporary=
compose_model=

# Removes unfinished manifest and Compose files when collection is interrupted.
cleanup() {
	[[ -z $temporary ]] || rm -f -- "$temporary"
	[[ -z $compose_model ]] || rm -f -- "$compose_model"
}

trap cleanup EXIT HUP INT TERM
install -d -m 0700 "$artifact_dir"
cd "$repo_dir"

if [[ -z $image || -z $auth_image ]]; then
	export ARRAYVPN_UID=${ARRAYVPN_UID:-$(id -u)}
	export ARRAYVPN_GID=${ARRAYVPN_GID:-$(id -g)}
	compose_model=$(mktemp "$artifact_dir/.build-manifest-compose.XXXXXX")
	docker compose "${compose_files[@]}" config --format json >"$compose_model"

	mapfile -t compose_images < <(
		python3 - "$compose_model" <<'PY'
import json
import pathlib
import sys

config = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(config["services"]["pku-array-vpn"]["image"])
print(config["services"]["array-auth"]["image"])
PY
	)

	[[ ${#compose_images[@]} -eq 2 ]] || {
		echo 'unable to resolve the two manifest image names' >&2
		exit 1
	}

	[[ -n $image ]] || image=${compose_images[0]}
	[[ -n $auth_image ]] || auth_image=${compose_images[1]}
	rm -f -- "$compose_model"
	compose_model=
fi

for required_image in "$image" "$auth_image"; do
	docker image inspect "$required_image" >/dev/null 2>&1 || {
		echo "make $required_image available first" >&2
		exit 64
	}
done

temporary=$(mktemp "$artifact_dir/.build-manifest.XXXXXX")

{
	printf '%s\n' '[locked sources]'
	sed -n '/^[A-Z0-9_]*=/p' "$repo_dir/versions.env"
	printf '%s\n' '[tunnel image]'

	docker image inspect --format \
		'image_id={{.Id}} os={{.Os}} architecture={{.Architecture}} size={{.Size}}' \
		"$image"

	printf '%s\n' '[tunnel runtime versions and hashes]'

	docker run --rm --network none --read-only \
		--cap-drop ALL --security-opt no-new-privileges:true \
		--entrypoint /bin/sh "$image" -eu -c '
            openconnect --version 2>&1

            sha256sum \
                /usr/local/sbin/openconnect \
                /usr/local/lib/libopenconnect.so.5.9.0 \
                /usr/local/bin/ocproxy \
                /usr/local/bin/array-auth-client \
                /usr/share/licenses/openconnect/COPYING.LGPL \
                /usr/share/licenses/ocproxy/LICENSE \
                /usr/share/licenses/ocproxy/AUTHORS \
                /usr/share/licenses/lwip/COPYING \
                /usr/share/licenses/pku-array-vpn-proxy/LICENSE \
                /usr/share/licenses/pku-array-vpn-proxy/NOTICE \
                /usr/share/licenses/pku-array-vpn-proxy/THIRD_PARTY_NOTICES.md
        '

	printf '%s\n' '[tunnel runtime apk packages]'

	docker run --rm --network none --read-only \
		--cap-drop ALL --security-opt no-new-privileges:true \
		--entrypoint /sbin/apk "$image" info -vv 2>/dev/null | LC_ALL=C sort

	printf '%s\n' '[authentication image]'

	docker image inspect --format \
		'image_id={{.Id}} os={{.Os}} architecture={{.Architecture}} size={{.Size}}' \
		"$auth_image"

	printf '%s\n' '[local-only iSecSP authentication runtime hashes]'

	docker run --rm --network none --read-only \
		--cap-drop ALL --security-opt no-new-privileges:true \
		--entrypoint /bin/sh "$auth_image" -eu -c '
			sha256sum \
				/usr/local/sbin/isecsp-auth-server \
				/usr/local/bin/isecsp-auth-client \
				/opt/isecsp/libvl3vpn.so \
				/opt/isecsp/libisec.so \
				/etc/arrayvpn/servercert-pins.txt \
				/usr/share/licenses/isecsp/THIRD_PARTY_LICENSES.txt \
				/usr/share/licenses/pku-array-vpn-proxy/LICENSE \
				/usr/share/licenses/pku-array-vpn-proxy/NOTICE \
				/usr/share/licenses/pku-array-vpn-proxy/THIRD_PARTY_NOTICES.md
		'

	printf '%s\n' '[authentication runtime deb packages]'

	docker run --rm --network none --read-only \
		--cap-drop ALL --security-opt no-new-privileges:true \
		--entrypoint /usr/bin/dpkg-query "$auth_image" -W 2>/dev/null |
		LC_ALL=C sort
} >"$temporary"

mv -f -- "$temporary" "$manifest"
temporary=
chmod 0600 "$manifest"
sha256sum "$manifest"
