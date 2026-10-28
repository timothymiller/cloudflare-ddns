# ---- Build ----
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev
# The release image ships this CA bundle. Fail the build rather than ship one
# that still trusts the distrusted emSign roots (removed in 20261020-r0).
RUN apk add --no-cache --upgrade \
    'ca-certificates>=20261020-r0' \
    'ca-certificates-bundle>=20261020-r0'
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked
RUN apk add --no-cache upx && upx --best --lzma target/release/cloudflare-ddns

# ---- Release ----
FROM scratch AS release
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/target/release/cloudflare-ddns /cloudflare-ddns
ENTRYPOINT ["/cloudflare-ddns", "--repeat"]
