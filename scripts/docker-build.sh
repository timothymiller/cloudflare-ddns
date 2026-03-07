#!/bin/bash
BASH_DIR=$(dirname $(realpath "${BASH_SOURCE}"))
docker build --platform linux/amd64 --tag thisismynameok/cloudflare-ddns:latest ${BASH_DIR}/../
