#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Prints bounded certificate metadata for manual SPKI rotation decisions.
set -Eeuo pipefail
umask 077
readonly array_host=arrayvpn.pku.edu.cn
inspect_tmp=$(mktemp -d /run/arrayvpn/inspect.XXXXXX)
candidates_file=$inspect_tmp/candidates
readonly tls_priority='NORMAL:-VERS-SSL3.0:+SHA256:%COMPAT:%UNSAFE_RENEGOTIATION:-3DES-CBC:-ARCFOUR-128'

# Removes all certificates and logs captured during inspection.
cleanup() {
	rm -rf -- "$inspect_tmp"
}

trap cleanup EXIT HUP INT TERM
/usr/local/bin/resolve-array.sh >"$candidates_file"
candidate_number=0

while IFS= read -r candidate_ip; do
	candidate_number=$((candidate_number + 1))
	cert_file=$inspect_tmp/peer-$candidate_number.pem
	gnutls_log=$inspect_tmp/gnutls-$candidate_number.log
	echo "candidate=$candidate_number ip=$candidate_ip"

	if ! timeout 15 gnutls-cli \
		--no-ca-verification \
		--priority="$tls_priority" \
		--sni-hostname="$array_host" \
		--save-cert="$cert_file" \
		-p 443 "$candidate_ip" \
		</dev/null >"$gnutls_log" 2>&1; then
		echo "tls_status=unavailable"
		continue
	fi

	openssl x509 -in "$cert_file" -noout \
		-subject -issuer -serial -dates -sha256 -fingerprint

	spki=$(
		openssl x509 -in "$cert_file" -pubkey -noout |
			openssl pkey -pubin -outform DER 2>/dev/null |
			openssl dgst -sha256 -binary |
			base64 | tr -d '\r\n'
	)

	echo "spki=pin-sha256:$spki"
done <"$candidates_file"

echo "No pin file was modified. Verify any new SPKI through an independent PKU channel."
