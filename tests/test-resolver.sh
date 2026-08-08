#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests DoH provider fallback, CNAME traversal, and non-public address filtering.
set -Eeuo pipefail
resolver=${1:-scripts/resolve-array.sh}
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
install -d -m 0700 "$repo_dir/artifacts"
test_root=$(mktemp -d "$repo_dir/artifacts/.resolver-test.XXXXXX")

# Removes only the randomized resolver fixture directory.
cleanup() {
	case "$test_root" in
	"$repo_dir"/artifacts/.resolver-test.*) rm -rf -- "$test_root" ;;
	*) echo 'refusing unsafe test cleanup' >&2 ;;
	esac
}

trap cleanup EXIT HUP INT TERM
install -d -m 0700 "$test_root/bin" "$test_root/run"

cat >"$test_root/bin/curl" <<'SH'
#!/usr/bin/env sh
set -eu
output=
url=

while test "$#" -gt 0; do
	case "$1" in
		-o) output=$2; shift 2 ;;
		https://*) url=$1; shift ;;
		*) shift ;;
	esac
done

test -n "$output"

case "$url" in
	*name=edge.example*)
		printf '%s\n' '{"Status":0,"Answer":[{"name":"edge.example.","type":1,"data":"111.205.231.51"}]}' >"$output"
		;;
	*)
		printf '%s\n' '{"Status":0,"Answer":[' \
			'{"name":"arrayvpn.pku.edu.cn.","type":1,"data":"198.18.0.7"},' \
			'{"name":"arrayvpn.pku.edu.cn.","type":1,"data":"10.0.0.1"},' \
			'{"name":"arrayvpn.pku.edu.cn.","type":1,"data":"106.120.124.249"},' \
			'{"name":"arrayvpn.pku.edu.cn.","type":5,"data":"edge.example."}' \
			']}' | tr -d '\n' >"$output"
		;;
esac
SH

chmod 0755 "$test_root/bin/curl"

actual=$(
	PATH="$test_root/bin:$PATH" \
		ARRAY_RUNTIME_DIR="$test_root/run" \
		"$resolver" 2>"$test_root/stderr"
)

expected=$(printf '%s\n%s' 106.120.124.249 111.205.231.51)
test "$actual" = "$expected"
grep -q 'DNS_FAKE_OR_NONPUBLIC_FILTERED' "$test_root/stderr"

if grep -Eq '198\.18\.|(^|[^0-9])10\.0\.0\.1' <<<"$actual"; then
	echo 'resolver emitted a fake or private address' >&2
	exit 1
fi

echo 'resolver_test=ok'
