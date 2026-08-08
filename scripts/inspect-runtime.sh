#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Inspects already-built images and ephemeral containers against hardening rules.
set -Eeuo pipefail
umask 077
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)
compose_files=(-f "$repo_dir/compose.yaml")

[[ $# -eq 0 ]] || {
	printf 'usage: inspect-runtime.sh\n' >&2
	exit 64
}

install -d -m 0700 "$repo_dir/artifacts"
test_dir=$(mktemp -d "$repo_dir/artifacts/.runtime-inspect.XXXXXX")
override_file=$test_dir/override.yaml
project_name=pku-array-inspect-$$
started=0

# Tears down only this inspection project and removes its synthetic secrets.
cleanup() {
	if ((started)); then
		docker compose -p "$project_name" "${compose_files[@]}" \
			-f "$override_file" down --volumes --remove-orphans \
			>/dev/null 2>&1 || :
	fi

	rm -rf -- "$test_dir"
}

trap cleanup EXIT HUP INT TERM
runtime_uid=$(id -u)
runtime_gid=$(id -g)

[[ $runtime_uid -ne 0 && $runtime_gid -ne 0 ]] || {
	echo 'runtime inspection requires a non-root user and group' >&2
	exit 64
}

export ARRAYVPN_UID=$runtime_uid
export ARRAYVPN_GID=$runtime_gid
cd "$repo_dir"
base_compose_json=$test_dir/base-compose.json

docker compose "${compose_files[@]}" config --format json \
	>"$base_compose_json"

mapfile -t runtime_images < <(
	python3 - "$base_compose_json" <<'PY'
import json
import pathlib
import sys

config = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(config["services"]["pku-array-vpn"]["image"])
print(config["services"]["array-auth"]["image"])
PY
)

[[ ${#runtime_images[@]} -eq 2 ]] || {
	echo 'unable to resolve the two runtime image names' >&2
	exit 1
}

tunnel_image=${runtime_images[0]}
auth_image=${runtime_images[1]}

for image in "$tunnel_image" "$auth_image"; do
	docker image inspect "$image" >/dev/null 2>&1 || {
		echo "make $image available first" >&2
		exit 64
	}

	[[ $(docker image inspect --format '{{.Config.User}}' "$image") == arrayvpn:arrayvpn ]] || {
		echo "$image does not use the named non-root image identity; rebuild it" >&2
		exit 64
	}
done

printf 'runtime-test-user' >"$test_dir/vpn_username"
printf 'runtime-test-password' >"$test_dir/vpn_password"
printf '12345X' >"$test_dir/id_card_last6"
printf '6789' >"$test_dir/phone_missing4"

chmod 0600 "$test_dir"/vpn_username "$test_dir"/vpn_password \
	"$test_dir"/id_card_last6 "$test_dir"/phone_missing4

cat >"$override_file" <<EOF
services:
  pku-array-vpn:
    entrypoint: ["/bin/sleep", "300"]
    ports: !reset []
    restart: "no"
    stop_grace_period: 1s

    healthcheck:
      disable: true

  array-auth:
    entrypoint: ["/bin/sleep", "300"]
    restart: "no"
    stop_grace_period: 1s

    healthcheck:
      disable: true

secrets:
  vpn_username:
    file: $test_dir/vpn_username

  vpn_password:
    file: $test_dir/vpn_password

  id_card_last6:
    file: $test_dir/id_card_last6

  phone_missing4:
    file: $test_dir/phone_missing4
EOF

runtime_compose_json=$test_dir/runtime-compose.json

docker compose -p "$project_name" "${compose_files[@]}" -f "$override_file" \
	config --format json >"$runtime_compose_json"

python3 - "$runtime_compose_json" "$tunnel_image" "$auth_image" <<'PY'
import json
import pathlib
import sys

config = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
tunnel = config["services"]["pku-array-vpn"]
auth = config["services"]["array-auth"]
assert not tunnel.get("ports")
assert auth["network_mode"] == "service:pku-array-vpn"
assert auth["depends_on"]["pku-array-vpn"]["restart"] is True
assert tunnel["image"] == sys.argv[2]
assert auth["image"] == sys.argv[3]
PY

started=1

docker compose -p "$project_name" "${compose_files[@]}" -f "$override_file" \
	up -d --no-build

tunnel_id=$(docker compose -p "$project_name" "${compose_files[@]}" \
	-f "$override_file" ps -q pku-array-vpn)

auth_id=$(docker compose -p "$project_name" "${compose_files[@]}" \
	-f "$override_file" ps -q array-auth)

[[ -n $tunnel_id && -n $auth_id ]] || {
	echo 'runtime inspection containers did not start' >&2
	exit 1
}

inspect_json=$test_dir/inspect.json
docker inspect "$tunnel_id" "$auth_id" >"$inspect_json"

python3 - "$inspect_json" "$runtime_uid:$runtime_gid" \
	"$tunnel_image" "$auth_image" <<'PY'
import json
import pathlib
import sys

tunnel, auth = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected_identity = sys.argv[2]
expected_tunnel_image = sys.argv[3]
expected_auth_image = sys.argv[4]

for item in (tunnel, auth):
    host = item["HostConfig"]
    config = item["Config"]
    assert config["User"] == expected_identity
    assert host["ReadonlyRootfs"] is True
    assert host["Privileged"] is False
    assert host.get("CapAdd") in (None, [])
    assert host["CapDrop"] == ["ALL"]
    assert not host.get("Devices")
    assert host.get("NetworkMode") != "host"
    assert "no-new-privileges" in " ".join(host.get("SecurityOpt") or [])

    for entry in config.get("Env") or []:
        key = entry.split("=", 1)[0]

        assert key not in {
            "vpn_username",
            "vpn_password",
            "id_card_last6",
            "phone_missing4",
        }

        assert "PASSWORD" not in key and "SECRET" not in key

assert not tunnel["HostConfig"].get("PortBindings")
assert not auth["HostConfig"].get("PortBindings")
assert auth["HostConfig"]["NetworkMode"].startswith("container:")
assert tunnel["Config"]["Image"] == expected_tunnel_image
assert auth["Config"]["Image"] == expected_auth_image
auth_tmpfs = auth["HostConfig"].get("Tmpfs") or {}
assert "/run/isecsp" in auth_tmpfs
tunnel_targets = {mount["Destination"] for mount in tunnel["Mounts"]}
auth_targets = {mount["Destination"] for mount in auth["Mounts"]}

secret_targets = {
    "/run/secrets/vpn_username",
    "/run/secrets/vpn_password",
    "/run/secrets/id_card_last6",
    "/run/secrets/phone_missing4",
}

assert secret_targets.isdisjoint(tunnel_targets)
assert secret_targets <= auth_targets
assert "/dev/net/tun" not in tunnel_targets | auth_targets
PY

docker exec --env EXPECTED_RUNTIME_ID="$runtime_uid:$runtime_gid" \
	"$tunnel_id" sh -eu -c '
    test "$(id -u):$(id -g)" = "$EXPECTED_RUNTIME_ID"
    test ! -e /build
    test ! -e /usr/local/include
    test ! -e /usr/local/share/doc
    test ! -e /usr/local/share/man

    for command_name in gcc git make python3; do
        ! command -v "$command_name" >/dev/null 2>&1
    done

    command -v openconnect >/dev/null
    command -v ocproxy >/dev/null
    command -v array-auth-client >/dev/null

    test "$(head -n 1 /usr/local/bin/openconnect-driver.exp)" = \
        "#!/usr/bin/expect -f"

    test -f /usr/share/licenses/openconnect/COPYING.LGPL
    test -f /usr/share/licenses/ocproxy/LICENSE
    test -f /usr/share/licenses/ocproxy/AUTHORS
    test -f /usr/share/licenses/lwip/COPYING
    test -f /usr/share/licenses/pku-array-vpn-proxy/LICENSE
    test -f /usr/share/licenses/pku-array-vpn-proxy/NOTICE
    test -f /usr/share/licenses/pku-array-vpn-proxy/THIRD_PARTY_NOTICES.md
    ! command -v isecsp-auth-client >/dev/null 2>&1
    test ! -e /run/secrets/vpn_username
    touch /run/arrayvpn/tmpfs-write-test
    rm /run/arrayvpn/tmpfs-write-test
'

docker exec --env EXPECTED_RUNTIME_ID="$runtime_uid:$runtime_gid" \
	"$auth_id" sh -eu -c '
    test "$(id -u):$(id -g)" = "$EXPECTED_RUNTIME_ID"
    command -v isecsp-auth-server >/dev/null
    command -v isecsp-auth-client >/dev/null
    test -f /opt/isecsp/libvl3vpn.so
    test -f /opt/isecsp/libisec.so
    test -f /usr/share/licenses/isecsp/THIRD_PARTY_LICENSES.txt
    test -f /usr/share/licenses/pku-array-vpn-proxy/LICENSE
    test -f /usr/share/licenses/pku-array-vpn-proxy/NOTICE
    test -f /usr/share/licenses/pku-array-vpn-proxy/THIRD_PARTY_NOTICES.md

    for command_name in gcc git make python3 dpkg-deb; do
        ! command -v "$command_name" >/dev/null 2>&1
    done

    for name in vpn_username vpn_password id_card_last6 phone_missing4; do
        test "$(stat -c "%u:%g:%a" "/run/secrets/$name")" = \
            "$EXPECTED_RUNTIME_ID:600"
    done

    test -f /etc/arrayvpn/servercert-pins.txt
    touch /run/isecsp/tmpfs-write-test
    rm /run/isecsp/tmpfs-write-test
'

for container_id in "$tunnel_id" "$auth_id"; do
	if docker exec --user 0 "$container_id" \
		sh -c 'touch /root-filesystem-write-test' >/dev/null 2>&1; then
		echo 'read-only root filesystem check failed' >&2
		exit 1
	fi
done

source_driver_sha=$(sha256sum "$repo_dir/scripts/openconnect-driver.exp" |
	awk '{print $1}')

image_driver_sha=$(docker exec "$tunnel_id" \
	sha256sum /usr/local/bin/openconnect-driver.exp | awk '{print $1}')

[[ $image_driver_sha == "$source_driver_sha" ]] || {
	echo 'tunnel image contains a stale OpenConnect driver; run make build' >&2
	exit 1
}

IMAGE=$tunnel_image "$repo_dir/tests/test-openconnect-driver.sh"
IMAGE=$tunnel_image "$repo_dir/tests/test-startup-session-rejection.sh"
auth_started_before=$(docker inspect --format '{{.State.StartedAt}}' "$auth_id")

docker compose -p "$project_name" "${compose_files[@]}" -f "$override_file" \
	restart pku-array-vpn >/dev/null

auth_started_after=$(docker inspect --format '{{.State.StartedAt}}' "$auth_id")

[[ $auth_started_after != "$auth_started_before" ]] || {
	echo 'authentication sidecar did not follow the tunnel restart' >&2
	exit 1
}

printf 'runtime_inspection=ok auth=isecsp-local\n'
