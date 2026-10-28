#!/bin/bash
BASH_DIR=$(dirname $(realpath "${BASH_SOURCE}"))
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7,linux/arm/v6,linux/ppc64le --tag timothyjmiller/cloudflare-ddns:latest ${BASH_DIR}/../
