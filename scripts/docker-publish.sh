#!/bin/bash
BASH_DIR=$(dirname $(realpath "${BASH_SOURCE}"))
set -euo pipefail

BASH_DIR=$(dirname $(realpath "${BASH_SOURCE}"))

# Ensure we have a buildx builder that supports multi-platform (docker-container driver)
# If 'multi-builder' doesn't exist, create it and bootstrap. Also register qemu via binfmt.
if ! docker buildx inspect multi-builder >/dev/null 2>&1; then
	echo "Creating buildx builder 'multi-builder' (driver: docker-container) and registering qemu/binfmt..."
	# register qemu emulators so cross-platform images can be built via emulation
	docker run --rm --privileged tonistiigi/binfmt --install all || true
	# create a builder using the container driver and set it as the current builder
	docker buildx create --name multi-builder --driver docker-container --use --bootstrap
else
	# make sure it's selected and ready
	docker buildx use multi-builder || true
	docker buildx inspect --bootstrap || true
fi

# Run the multi-platform build and push
docker buildx build \
	--platform linux/ppc64le,linux/s390x,linux/386,linux/arm/v6,linux/arm/v7,linux/arm64/v8,linux/amd64 \
	--tag thisismynameok/cloudflare-ddns:latest \
	--push "${BASH_DIR}/../"
