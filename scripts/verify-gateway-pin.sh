#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Verifies one resolved gateway against the operator-maintained SPKI allowlist.
set -Eeuo pipefail
umask 077
readonly array_host=arrayvpn.pku.edu.cn
candidate_ip=${1:-}
pin_file=${SERVERCERT_PIN_FILE:-/etc/arrayvpn/servercert-pins.txt}
verify_tmp=$(mktemp -d /run/arrayvpn/cert.XXXXXX)
cert_file=$verify_tmp/peer-chain.pem
gnutls_log=$verify_tmp/gnutls.log
readonly tls_priority='NORMAL:-VERS-SSL3.0:+SHA256:%COMPAT:%UNSAFE_RENEGOTIATION:-3DES-CBC:-ARCFOUR-128'

# Removes captured peer certificates and TLS diagnostics.
cleanup() {
	rm -rf -- "$verify_tmp"
}

trap cleanup EXIT HUP INT TERM

if [[ ! $candidate_ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
	echo "TLS_CANDIDATE_INVALID" >&2
	exit 64
fi

if [[ ! -f $pin_file ]] || [[ -L $pin_file ]]; then
	echo "TLS_PIN_FILE_INVALID" >&2
	exit 64
fi

if grep -Ev '^pin-sha256:[A-Za-z0-9+/]{43}=$' "$pin_file" |
	grep -q .; then
	echo "TLS_PIN_FILE_INVALID" >&2
	exit 64
fi

if [[ $(grep -Ec '^pin-sha256:' "$pin_file") -lt 1 ]]; then
	echo "TLS_PIN_FILE_EMPTY" >&2
	exit 64
fi

if ! timeout 15 gnutls-cli \
	--no-ca-verification \
	--priority="$tls_priority" \
	--sni-hostname="$array_host" \
	--save-cert="$cert_file" \
	-p 443 "$candidate_ip" \
	</dev/null >"$gnutls_log" 2>&1; then
	echo "TLS_PREFLIGHT_UNAVAILABLE" >&2
	exit 75
fi

if [[ ! -s $cert_file ]]; then
	echo "TLS_PREFLIGHT_NO_CERTIFICATE" >&2
	exit 75
fi

spki=$(
	openssl x509 -in "$cert_file" -pubkey -noout |
		openssl pkey -pubin -outform DER 2>/dev/null |
		openssl dgst -sha256 -binary |
		base64 | tr -d '\r\n'
)

if [[ ! $spki =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
	echo "TLS_PREFLIGHT_SPKI_ERROR" >&2
	exit 75
fi

if ! grep -Fqx "pin-sha256:$spki" "$pin_file"; then
	echo "TLS_PIN_MISMATCH" >&2
	exit 64
fi

printf '%s\n' "$candidate_ip"
