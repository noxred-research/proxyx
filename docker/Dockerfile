# syntax=docker/dockerfile:1.7
#
# One image with both binaries: `proxyx` (gateway, warmer, control, limiter, migrate)
# and `proxyx-intercept` (the session proxy). Build from the repository root:
#
#   docker build -f docker/Dockerfile -t proxyx:dev .
#
# Select a role with the command, for example `proxyx gateway` or `proxyx-intercept`.

# Base images are pinned by manifest-list digest; Dependabot proposes digest updates.
FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS builder
# cmake, clang and perl build BoringSSL (the session proxy's upstream TLS stack);
# librdkafka needs libssl-dev, libsasl2-dev and zlib; protoc is vendored by the workspace.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential cmake clang libclang-dev perl pkg-config protobuf-compiler \
        libssl-dev libsasl2-dev zlib1g-dev libzstd-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p proxyx -p proxyx-intercept \
    && install -D -m 0755 target/release/proxyx /out/proxyx \
    && install -D -m 0755 target/release/proxyx-intercept /out/proxyx-intercept

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS runtime
# openssl and curl are used by the dev compose stack (CA generation, health checks);
# libssl3 is linked by the control plane's Kafka client.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 libsasl2-2 openssl curl tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 proxyx \
    && useradd --system --uid 10001 --gid proxyx --home-dir /var/lib/proxyx --create-home --shell /usr/sbin/nologin proxyx \
    && mkdir -p /etc/proxyx/data /etc/proxyx/secrets /var/lib/proxyx/sqlite \
    && chown -R proxyx:proxyx /etc/proxyx /var/lib/proxyx
COPY --from=builder /out/proxyx /out/proxyx-intercept /usr/local/bin/
LABEL org.opencontainers.image.title="ProxyX" \
      org.opencontainers.image.description="Proxy gateway, session proxy, control plane and rate-limit service" \
      org.opencontainers.image.source="https://github.com/noxred-research/proxyx" \
      org.opencontainers.image.url="https://proxyx.dev" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
USER proxyx:proxyx
WORKDIR /var/lib/proxyx
# Gateway: CONNECT 8080, SOCKS5 1080, probe 8082, control API 8081, ops 8888.
# Session proxy: CONNECT 8443, SOCKS5 1080, admin 8888. Control plane: API 9000, ingester health 9001.
# Limiter: 39091.
EXPOSE 8080 8081 8082 8443 8888 9000 9001 1080 39091
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["proxyx", "--help"]
