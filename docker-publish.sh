#!/bin/bash
docker buildx build --platform linux/ppc64le,linux/s390x,linux/386,linux/arm/v6,linux/arm/v7,linux/arm64/v8,linux/amd64 --tag timothyjmiller/cloudflare-ddns:latest --push .
