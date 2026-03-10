# ---- Build ----
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

# ---- Release ----
FROM alpine:latest AS release
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/target/release/cloudflare-ddns /usr/local/bin/cloudflare-ddns
CMD ["cloudflare-ddns", "--repeat"]
