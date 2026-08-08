#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Captures and compares host-visible WSL and Windows network configuration.
set -Eeuo pipefail
umask 077
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)

# Prints the supported snapshot action and exits with a usage error.
usage() {
	echo 'usage: ./scripts/network-snapshot.sh before|after|compare' >&2
	exit 64
}

[[ $# -eq 1 ]] || usage
action=$1
cd "$repo_dir"
install -d -m 0700 artifacts

if [[ $action == compare ]]; then
	[[ -f artifacts/network-before.snapshot &&
		-f artifacts/network-after.snapshot ]] || {
		echo 'capture both before and after snapshots first' >&2
		exit 64
	}

	if diff -u artifacts/network-before.snapshot \
		artifacts/network-after.snapshot; then
		echo 'network_snapshot_check=unchanged'
	else
		echo 'network_snapshot_check=changed' >&2
		exit 1
	fi

	exit 0
fi

[[ $action == before || $action == after ]] || usage
snapshot=artifacts/network-$action.snapshot
temporary=$(mktemp artifacts/.network-snapshot.XXXXXX)
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM

{
	echo '[WSL resolv.conf link]'
	readlink /etc/resolv.conf 2>/dev/null || echo '(regular file)'
	echo '[WSL resolv.conf]'
	sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' /etc/resolv.conf
	echo '[WSL IPv4 addresses]'
	ip -o -4 address show | awk '{print $2, $3, $4, $5, $6}' | sort
	echo '[WSL IPv4 main routes]'
	ip -4 route show table main | sort
	echo '[Windows network]'

	if command -v powershell.exe >/dev/null 2>&1; then
		powershell.exe -NoProfile -NonInteractive -Command '
            $dns = Get-DnsClientServerAddress -AddressFamily IPv4 |
                Sort-Object InterfaceIndex |
                Select-Object InterfaceIndex, InterfaceAlias, ServerAddresses

            $routes = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" |
                Sort-Object InterfaceIndex, NextHop |
                Select-Object InterfaceIndex, NextHop, RouteMetric

            $addresses = Get-NetIPAddress -AddressFamily IPv4 |
                Sort-Object InterfaceIndex, IPAddress |
                Select-Object InterfaceIndex, InterfaceAlias, IPAddress, PrefixLength

            $interfaces = Get-NetIPInterface -AddressFamily IPv4 |
                Sort-Object InterfaceIndex |
                Select-Object InterfaceIndex, InterfaceAlias, NlMtu, InterfaceMetric, AutomaticMetric, Dhcp, ConnectionState

            [ordered]@{
                dns = @($dns)
                default_routes = @($routes)
                addresses = @($addresses)
                interfaces = @($interfaces)
            } | ConvertTo-Json -Depth 5 -Compress
        ' | tr -d '\r'
	else
		echo '(powershell.exe unavailable)'
	fi
} >"$temporary"

mv -f -- "$temporary" "$snapshot"
chmod 0600 "$snapshot"
sha256sum "$snapshot"
