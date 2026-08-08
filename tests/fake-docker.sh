#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Emulates the Docker CLI surface used by the build preflight tests.
set -Eeuo pipefail

echo "ALPINE_MIRROR=${ALPINE_MIRROR:-} UBUNTU_APT_MIRROR=${UBUNTU_APT_MIRROR:-} UBUNTU_IMAGE=${UBUNTU_IMAGE:-} docker $*" \
	>>"$FAKE_DOCKER_LOG"

if [[ ${1:-} == compose ]]; then
	exit 0
fi

exit 64
