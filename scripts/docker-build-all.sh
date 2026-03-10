#!/bin/bash
BASH_DIR=$(dirname $(realpath "${BASH_SOURCE}"))
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 --tag timothyjmiller/cloudflare-ddns:latest ${BASH_DIR}/../
