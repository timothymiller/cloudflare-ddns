# ---- Build ----
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

# ---- Release ----
FROM scratch AS release
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/target/release/cloudflare-ddns /cloudflare-ddns
ENTRYPOINT ["/cloudflare-ddns", "--repeat"]
