#!/bin/bash
BASH_DIR=$(dirname $(realpath "${BASH_SOURCE}"))
VERSION=$(grep '^version' ${BASH_DIR}/../Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/ppc64le \
  --tag timothyjmiller/cloudflare-ddns:latest \
  --tag timothyjmiller/cloudflare-ddns:${VERSION} \
  --push ${BASH_DIR}/../
