# SPDX-License-Identifier: Apache-2.0
# Defines operator-owned build entry points and non-building verification targets.
.PHONY: check-static compose-check build-check build auth-build-check \
	auth-build test inspect-runtime build-manifest post-build-check acceptance \
	clean-runtime

check-static:
	./scripts/check-static.sh

compose-check:
	./scripts/check-compose.sh

build-check:
	./scripts/build.sh --check

build:
	./scripts/build.sh

auth-build-check:
	./scripts/build.sh --check --auth-only

auth-build:
	./scripts/build.sh --auth-only

test: check-static compose-check

inspect-runtime:
	./scripts/inspect-runtime.sh

build-manifest:
	./scripts/build-manifest.sh

# Deliberately excludes the build target. The operator remains the only party
# that starts a Docker build; this target checks an already-built local image.
post-build-check: test build-check inspect-runtime build-manifest

acceptance:
	./scripts/acceptance.sh

clean-runtime:
	docker compose down --remove-orphans
