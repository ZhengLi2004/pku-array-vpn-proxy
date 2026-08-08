#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Resolves real public Array gateway addresses through independent JSON DoH.
set -Eeuo pipefail
umask 077
readonly array_host=arrayvpn.pku.edu.cn
alidns_url=${ALIDNS_DOH_URL:-https://dns.alidns.com/resolve}
cloudflare_url=${CLOUDFLARE_DOH_URL:-https://cloudflare-dns.com/dns-query}
runtime_dir=${ARRAY_RUNTIME_DIR:-/run/arrayvpn}

if [[ $runtime_dir != /* || ! -d $runtime_dir || -L $runtime_dir ]]; then
	echo "DNS_RUNTIME_DIR_INVALID" >&2
	exit 64
fi

doh_tmp=$(mktemp -d "$runtime_dir/doh.XXXXXX")
candidates_file=$doh_tmp/candidates
sorted_file=$doh_tmp/candidates.sorted
declare -A doh_seen=()

# Removes provider responses and the deduplicated candidate workspace.
cleanup() {
	rm -rf -- "$doh_tmp"
}

trap cleanup EXIT HUP INT TERM

if [[ ! $array_host =~ ^[A-Za-z0-9.-]+$ ]] ||
	[[ $array_host == .* ]] || [[ $array_host == *..* ]]; then
	echo "DNS_CONFIG_INVALID" >&2
	exit 64
fi

# Rejects private, reserved, documentation, multicast, and Clash fake-IP space.
#
# Args:
#   $1: Candidate dotted-quad text.
#
# Returns:
#   Zero only for a syntactically valid public IPv4 address.
is_public_ipv4() {
	awk -F. '
	# Terminates validation as soon as one reserved-address rule matches.
	function bad() { exit 1 }
	NF != 4 { bad() }

	{
		for (i = 1; i <= 4; i++) {
			if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255)
				bad()
		}

		a=$1; b=$2; c=$3

		if (a == 0 || a == 10 || a == 127 || a >= 224)
			bad()

		if (a == 100 && b >= 64 && b <= 127)
			bad()

		if (a == 169 && b == 254)
			bad()

		if (a == 172 && b >= 16 && b <= 31)
			bad()

		if (a == 192 && (b == 0 || b == 168))
			bad()

		if (a == 192 && b == 0 && c == 2)
			bad()

		if (a == 198 && (b == 18 || b == 19))
			bad()

		if (a == 198 && b == 51 && c == 100)
			bad()

		if (a == 203 && b == 0 && c == 113)
			bad()

		exit 0
	}' <<<"$1"
}

# Resolves one name through a bounded DNS-over-HTTPS provider and follows CNAMEs.
#
# Args:
#   $1: Provider label used only in sanitized diagnostics.
#   $2: HTTPS JSON-DoH endpoint.
#   $3: DNS name to query.
#   $4: Current CNAME recursion depth.
#
# Globals:
#   Appends public A records to candidates_file and records visited names in
#   doh_seen. Individual provider failures do not expose response bodies.
#
# Returns:
#   Zero after a valid response (including bounded CNAME traversal); nonzero
#   when this provider cannot supply a valid DNS response.
query_provider() {
	local provider=$1
	local base_url=$2
	local query_name=$3
	local depth=$4
	local seen_key=$provider:$query_name
	local response_file candidate cname

	if ((depth > 2)) || [[ ${doh_seen[$seen_key]+present} ]]; then
		return 0
	fi

	doh_seen[$seen_key]=1
	response_file=$doh_tmp/$provider-$depth-${RANDOM}.json

	if ! curl --fail --silent --show-error \
		--proto '=https' --tlsv1.2 \
		--connect-timeout 5 --max-time 10 --max-filesize 65536 \
		-H 'accept: application/dns-json' \
		"$base_url?name=$query_name&type=A" \
		-o "$response_file"; then
		echo "DNS_PROVIDER_UNAVAILABLE provider=$provider" >&2
		return 1
	fi

	if ! jq -e '(.Status // 1) == 0' "$response_file" >/dev/null; then
		echo "DNS_PROVIDER_ERROR provider=$provider" >&2
		return 1
	fi

	while IFS= read -r candidate; do
		if is_public_ipv4 "$candidate"; then
			printf '%s\n' "$candidate" >>"$candidates_file"
		else
			echo "DNS_FAKE_OR_NONPUBLIC_FILTERED provider=$provider" >&2
		fi
	done < <(
		jq -r --arg q "$query_name" '
			.Answer[]? |
			select(.type == 1) |
			select(
				((.name // "") | ascii_downcase | rtrimstr(".")) ==
				($q | ascii_downcase | rtrimstr("."))
			) |
			.data
		' "$response_file"
	)

	while IFS= read -r cname; do
		[[ $cname =~ ^[A-Za-z0-9.-]+$ ]] || continue
		query_provider "$provider" "$base_url" "$cname" $((depth + 1)) || :
	done < <(
		jq -r --arg q "$query_name" '
			.Answer[]? |
			select(.type == 5) |
			select(
				((.name // "") | ascii_downcase | rtrimstr(".")) ==
				($q | ascii_downcase | rtrimstr("."))
			) |
			.data | rtrimstr(".")
		' "$response_file"
	)
}

: >"$candidates_file"
query_provider alidns "$alidns_url" "$array_host" 0 || :
query_provider cloudflare "$cloudflare_url" "$array_host" 0 || :
sort -u "$candidates_file" >"$sorted_file"

if [[ ! -s $sorted_file ]]; then
	echo "DNS_NO_PUBLIC_A_RECORDS" >&2
	exit 75
fi

head -n 16 "$sorted_file"
