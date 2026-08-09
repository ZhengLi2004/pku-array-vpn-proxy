#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Verifies the rendered Compose security, image, and secret-mount contract.
set -Eeuo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)

[[ $# -eq 0 ]] || {
	printf 'usage: check-compose.sh\n' >&2
	exit 64
}

install -d -m 0700 "$repo_dir/artifacts"
test_dir=$(mktemp -d "$repo_dir/artifacts/.compose-check.XXXXXX")
compose_json=$test_dir/compose.json
override_compose_json=$test_dir/compose-override.json
runtime_uid=$(id -u)
runtime_gid=$(id -g)

[[ $runtime_uid -ne 0 && $runtime_gid -ne 0 ]] || {
	echo 'Compose checks require a non-root user and group.' >&2
	exit 64
}

export ARRAYVPN_UID=$runtime_uid
export ARRAYVPN_GID=$runtime_gid

# Removes the private rendered Compose model after validation.
cleanup() {
	rm -rf -- "$test_dir"
}

trap cleanup EXIT HUP INT TERM
cd "$repo_dir"

ALPINE_MIRROR= \
	UBUNTU_APT_MIRROR= \
	UBUNTU_IMAGE= \
	PKU_ARRAY_VPN_IMAGE= \
	VPN_DATA_TRANSPORT= \
	docker compose config --format json >"$compose_json"

ALPINE_MIRROR=https://mirror.example/alpine \
	UBUNTU_APT_MIRROR=https://mirror.example/ubuntu \
	UBUNTU_IMAGE=registry.example/ubuntu:24.04@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
	PKU_ARRAY_VPN_IMAGE=ghcr.io/example/pku-array-vpn-proxy:v1 \
	VPN_DATA_TRANSPORT=auto \
	docker compose config --format json >"$override_compose_json"

python3 - "$compose_json" "$override_compose_json" \
	"$runtime_uid:$runtime_gid" <<'PY'
import json
import pathlib
import sys

config = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
override_config = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
runtime_identity = sys.argv[3]
tunnel = config["services"]["pku-array-vpn"]
auth = config["services"]["array-auth"]
assert set(config["services"]) == {"pku-array-vpn", "array-auth"}

for service in (tunnel, auth):
    assert service["read_only"] is True
    assert service["user"] == runtime_identity
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service.get("privileged", False) is False
    assert not service.get("devices")
    assert service.get("network_mode") != "host"

assert tunnel["build"]["dockerfile"] == "Dockerfile"
assert tunnel["build"]["args"] == {"ALPINE_MIRROR": ""}
assert tunnel["image"] == "pku-array-vpn-proxy:local"
assert tunnel["environment"]["VPN_DATA_TRANSPORT"] == "tls"

assert override_config["services"]["pku-array-vpn"]["build"]["args"] == {
    "ALPINE_MIRROR": "https://mirror.example/alpine"
}

assert (
    override_config["services"]["pku-array-vpn"]["image"]
    == "ghcr.io/example/pku-array-vpn-proxy:v1"
)

assert (
    override_config["services"]["pku-array-vpn"]["environment"]
    ["VPN_DATA_TRANSPORT"]
    == "auto"
)

assert auth["build"]["dockerfile"] == "Dockerfile.isecsp-auth"

assert auth["build"]["args"] == {
    "UBUNTU_APT_MIRROR": "",
    "UBUNTU_IMAGE": (
        "ubuntu:24.04@sha256:"
        "561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea"
    ),
}

assert auth["image"] == "pku-array-vpn-auth:isecsp-local"

assert auth["healthcheck"]["test"] == [
    "CMD",
    "/usr/local/bin/isecsp-auth-client",
    "--healthcheck",
]

assert override_config["services"]["array-auth"]["build"]["args"] == {
    "UBUNTU_APT_MIRROR": "https://mirror.example/ubuntu",
    "UBUNTU_IMAGE": (
        "registry.example/ubuntu:24.04@sha256:"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ),
}

assert auth["network_mode"] == "service:pku-array-vpn"

assert auth["depends_on"]["pku-array-vpn"] == {
    "condition": "service_started",
    "required": True,
    "restart": True,
}

assert not auth.get("ports")
ports = tunnel["ports"]
assert len(ports) == 1
port = ports[0]
assert port["host_ip"] == "127.0.0.1"
assert str(port["published"]) == "11080"
assert int(port["target"]) == 1080
assert port["protocol"] == "tcp"
secret_names = {"vpn_username", "vpn_password", "id_card_last6", "phone_missing4"}
assert set(config["secrets"]) == secret_names
assert not tunnel.get("secrets")
assert {item["source"] for item in auth["secrets"]} == secret_names

for service in (tunnel, auth):
    environment = service.get("environment", {})
    assert secret_names.isdisjoint(environment)
    assert all("PASSWORD" not in key and "SECRET" not in key for key in environment)

assert "ARRAY_HOST" not in tunnel.get("environment", {})
assert any(item.startswith("/run/arrayvpn:") for item in tunnel["tmpfs"])
assert any(item.startswith("/tmp:") for item in tunnel["tmpfs"])
assert any(item.startswith("/run/isecsp:") for item in auth["tmpfs"])
assert any(item.startswith("/tmp:") for item in auth["tmpfs"])

for service in (tunnel, auth):
    runtime_tmpfs = next(item for item in service["tmpfs"] if item.startswith("/run/"))
    uid, gid = runtime_identity.split(":")
    assert f"uid={uid}" in runtime_tmpfs
    assert f"gid={gid}" in runtime_tmpfs
PY

printf 'compose_check=ok auth=isecsp-local\n'
