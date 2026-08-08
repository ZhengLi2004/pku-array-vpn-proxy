#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Validates and stages a user-obtained official iSecSP package for local builds.
set -Eeuo pipefail
umask 077
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)
destination_dir=$repo_dir/local
destination=$destination_dir/iSecSP_ubuntu_2.4.0.deb
expected_deb_sha=4b062dfa4a9a89cbb60d538b1cc3cb47d014ff91e907db16c891fcd9ebd91d6c
expected_vl3_sha=0a20b9f9760c845e805fdbdded968100344c2cc3026ef1134dd81ae664135787
expected_isec_sha=cf9df4e6726d95c2f06d38efe5a07684520c90300b147e8915a6c130d7c9469e
audit_dir=

# Prints the local package-staging interface.
usage() {
	cat <<'EOF'
Usage: ./scripts/prepare-isecsp.sh /path/to/iSecSP_ubuntu_2.4.0.deb

The package must be obtained by the user from an authorized source. This
command performs static extraction only; it never executes package scripts or
vendor binaries. The validated copy remains under the Git-ignored local/ path.
EOF
}

# Reports a bounded preparation failure and exits.
fail() {
	printf 'iSecSP preparation failed: %s\n' "$*" >&2
	exit 1
}

# Removes only this invocation's private audit directory.
cleanup() {
	if [[ -n $audit_dir && $audit_dir == "$repo_dir"/artifacts/.isecsp-prepare.* ]]; then
		rm -rf -- "$audit_dir"
	fi
}

trap cleanup EXIT HUP INT TERM

[[ $# -eq 1 ]] || {
	usage >&2
	exit 2
}

source_path=$1
[[ -f $source_path && ! -L $source_path ]] ||
	fail 'source must be a regular, non-symlink file'

for command_name in dpkg-deb sha256sum; do
	command -v "$command_name" >/dev/null 2>&1 ||
		fail "$command_name is required"
done

[[ $(sha256sum "$source_path" | awk '{print $1}') == "$expected_deb_sha" ]] ||
	fail 'package SHA-256 does not match the audited PKU package'

[[ $(dpkg-deb -f "$source_path" Package) == isecsp ]] ||
	fail 'unexpected package name'

[[ $(dpkg-deb -f "$source_path" Version) == 2.4.0 ]] ||
	fail 'unexpected package version'

[[ $(dpkg-deb -f "$source_path" Architecture) == amd64 ]] ||
	fail 'unexpected package architecture'

install -d -m 0700 "$repo_dir/artifacts"
audit_dir=$(mktemp -d "$repo_dir/artifacts/.isecsp-prepare.XXXXXX")
dpkg-deb -x "$source_path" "$audit_dir/extracted"
vl3_library=$audit_dir/extracted/opt/iSecSP/libvl3vpn.so
isec_library=$audit_dir/extracted/opt/iSecSP/libisec.so

[[ -f $vl3_library && ! -L $vl3_library ]] ||
	fail 'package lacks the expected libvl3vpn.so'

[[ -f $isec_library && ! -L $isec_library ]] ||
	fail 'package lacks the expected libisec.so'

[[ $(sha256sum "$vl3_library" | awk '{print $1}') == "$expected_vl3_sha" ]] ||
	fail 'libvl3vpn.so SHA-256 does not match the audited component'

[[ $(sha256sum "$isec_library" | awk '{print $1}') == "$expected_isec_sha" ]] ||
	fail 'libisec.so SHA-256 does not match the audited component'

install -d -m 0700 "$destination_dir"

if [[ $(realpath -e -- "$source_path") == $(realpath -m -- "$destination") ]]; then
	chmod 0600 "$destination"
else
	[[ ! -e $destination ]] ||
		fail 'destination already exists; remove it explicitly before replacement'

	install -m 0600 "$source_path" "$destination"
fi

printf 'isecsp_package=ready sha256=%s distribution=local-only\n' \
	"$expected_deb_sha"
