#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Performs the operator-assisted local security and connectivity acceptance.
set -Eeuo pipefail

[[ $# -eq 0 ]] || {
	echo 'usage: ./scripts/acceptance.sh' >&2
	exit 64
}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)
health_url=${HEALTHCHECK_URL:-https://its.pku.edu.cn/service_1_vpn2.jsp}

[[ -n ${TEST_TARGET_HOST:-} && -n ${TEST_TARGET_PORT:-} ]] || {
	echo 'set TEST_TARGET_HOST and TEST_TARGET_PORT locally before acceptance' >&2
	exit 64
}

cd "$repo_dir"
install -d -m 0700 artifacts
compose_json=$(mktemp "$repo_dir/artifacts/.acceptance-compose.XXXXXX")
inspect_json=$(mktemp "$repo_dir/artifacts/.acceptance-inspect.XXXXXX")
trap 'rm -f -- "$compose_json" "$inspect_json"' EXIT HUP INT TERM
docker compose config --format json >"$compose_json"
tunnel_id=$(docker compose ps -q pku-array-vpn)
auth_id=$(docker compose ps -q array-auth)

[[ -n $tunnel_id ]] || {
	echo 'pku-array-vpn is not running' >&2
	exit 1
}

[[ -n $auth_id ]] || {
	echo 'array-auth is not running' >&2
	exit 1
}

curl --fail --silent --show-error \
	--connect-timeout 10 --max-time 30 \
	--socks5-hostname 127.0.0.1:11080 \
	--head "$health_url" >/dev/null

python3 scripts/check-socks-target.py
docker inspect "$tunnel_id" "$auth_id" >"$inspect_json"

python3 - "$inspect_json" "$compose_json" <<'PY'
import json
import pathlib
import sys


# Reports a stable assertion name without invoking Python's traceback hook.
def require(condition, reason):
    if not condition:
        raise SystemExit(f"acceptance_runtime_check=failed reason={reason}")


containers = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
require(len(containers) == 2, "CONTAINER_COUNT")
tunnel, auth = containers
compose = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
expected_tunnel_image = compose["services"]["pku-array-vpn"]["image"]
expected_auth_image = compose["services"]["array-auth"]["image"]
runtime_identity = tunnel["Config"]["User"]
identity_parts = runtime_identity.split(":")

require(
    len(identity_parts) == 2 and all(part.isdigit() for part in identity_parts),
    "RUNTIME_IDENTITY_FORMAT",
)

runtime_uid, runtime_gid = (int(part) for part in identity_parts)
require(runtime_uid > 0 and runtime_gid > 0, "RUNTIME_IDENTITY_ROOT")

for item in (tunnel, auth):
    host = item["HostConfig"]
    config = item["Config"]
    service = config["Labels"]["com.docker.compose.service"]
    require(config["User"] == runtime_identity, f"{service}_IDENTITY")
    require(host["ReadonlyRootfs"] is True, f"{service}_ROOTFS")
    require(host["Privileged"] is False, f"{service}_PRIVILEGED")
    require(host.get("CapAdd") in (None, []), f"{service}_CAP_ADD")
    require(host["CapDrop"] == ["ALL"], f"{service}_CAP_DROP")
    require(not host.get("Devices"), f"{service}_DEVICES")

    require(
        "no-new-privileges" in " ".join(host.get("SecurityOpt") or []),
        f"{service}_NO_NEW_PRIVILEGES",
    )

    for entry in config.get("Env") or []:
        key = entry.split("=", 1)[0]

        require(
            key
            not in {
                "vpn_username",
                "vpn_password",
                "id_card_last6",
                "phone_missing4",
            },
            f"{service}_SECRET_ENV",
        )

        require(
            "PASSWORD" not in key and "SECRET" not in key,
            f"{service}_SENSITIVE_ENV",
        )

bindings = tunnel["HostConfig"]["PortBindings"]["1080/tcp"]

require(
    bindings == [{"HostIp": "127.0.0.1", "HostPort": "11080"}],
    "SOCKS_BINDING",
)

require(not auth["HostConfig"].get("PortBindings"), "AUTH_PORT_BINDING")

require(
    auth["HostConfig"]["NetworkMode"].startswith("container:"),
    "AUTH_NETWORK_MODE",
)

require(tunnel["Config"]["Image"] == expected_tunnel_image, "TUNNEL_IMAGE")
require(auth["Config"]["Image"] == expected_auth_image, "AUTH_IMAGE")

secret_targets = {
    "/run/secrets/vpn_username",
    "/run/secrets/vpn_password",
    "/run/secrets/id_card_last6",
    "/run/secrets/phone_missing4",
}

tunnel_targets = {mount["Destination"] for mount in tunnel["Mounts"]}
auth_targets = {mount["Destination"] for mount in auth["Mounts"]}
require(secret_targets.isdisjoint(tunnel_targets), "TUNNEL_SECRET_MOUNT")
require(secret_targets <= auth_targets, "AUTH_SECRET_MOUNT")
require("/dev/net/tun" not in tunnel_targets | auth_targets, "TUN_DEVICE")
require("/run/isecsp" in (auth["HostConfig"].get("Tmpfs") or {}), "AUTH_TMPFS")
PY

if command -v powershell.exe >/dev/null 2>&1; then
	powershell.exe -NoProfile -NonInteractive -Command '
        $listeners = @(Get-NetTCPConnection -State Listen -LocalPort 11080 -ErrorAction Stop)
        if ($listeners.Count -eq 0) { throw "no Windows listener on port 11080" }
        $bad = @($listeners | Where-Object { $_.LocalAddress -ne "127.0.0.1" })
        if ($bad.Count -ne 0) { throw "port 11080 is published beyond IPv4 loopback" }
        "windows_listener_check=ok address=127.0.0.1 port=11080"
    '
fi

echo 'acceptance=ok auth=isecsp-local'
