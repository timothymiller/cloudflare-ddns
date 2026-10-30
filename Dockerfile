# ---- CA bundle ----
# Certificates are architecture-independent, so fetch them on the build host.
FROM --platform=$BUILDPLATFORM alpine:3.24 AS certs
# The release image ships this CA bundle. Fail the build rather than ship one
# that still trusts the distrusted emSign roots (removed in 20261020-r0).
RUN apk add --no-cache --upgrade \
    'ca-certificates>=20261020-r0' \
    'ca-certificates-bundle>=20261020-r0'

# ---- Build ----
# Cross-compile on the build host instead of emulating each target under QEMU.
# zig supplies the musl C toolchain that ring needs for every target, which is
# what makes 32-bit ARM possible (rust:alpine has no arm/v6 or arm/v7 image).
FROM --platform=$BUILDPLATFORM ghcr.io/rust-cross/cargo-zigbuild:0.23.4 AS builder
ARG TARGETPLATFORM
RUN apt-get update \
    && apt-get install -y --no-install-recommends upx-ucl \
    && rm -rf /var/lib/apt/lists/*
RUN case "$TARGETPLATFORM" in \
        linux/amd64)   echo x86_64-unknown-linux-musl ;; \
        linux/arm64)   echo aarch64-unknown-linux-musl ;; \
        linux/arm/v7)  echo armv7-unknown-linux-musleabihf ;; \
        linux/arm/v6)  echo arm-unknown-linux-musleabihf ;; \
        linux/ppc64le) echo powerpc64le-unknown-linux-musl ;; \
        *) echo "Unsupported platform: $TARGETPLATFORM" >&2; exit 1 ;; \
    esac > /rust-target \
    && rustup target add "$(cat /rust-target)"
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo zigbuild --release --locked --target "$(cat /rust-target)" \
    && cp "target/$(cat /rust-target)/release/cloudflare-ddns" /cloudflare-ddns \
    && upx --best --lzma /cloudflare-ddns
# scratch has no /tmp; the health file lives there.
RUN mkdir /scratch-tmp

# ---- Release ----
FROM scratch AS release
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /cloudflare-ddns /cloudflare-ddns
# World-writable + sticky like a normal /tmp, so --user overrides (TrueNAS
# runs apps as 568) can still write the health file.
COPY --from=builder --chmod=1777 /scratch-tmp /tmp
# Unprivileged "nobody", matching the Helm chart and k8s manifests. Nothing
# here needs root: no low ports, and interface detection reads netlink.
USER 65534:65534
HEALTHCHECK --interval=1m --timeout=10s --start-period=2m --retries=3 \
    CMD ["/cloudflare-ddns", "--health"]
ENTRYPOINT ["/cloudflare-ddns", "--repeat"]
