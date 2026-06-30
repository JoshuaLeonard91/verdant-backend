# ---------------------------------------------------------------------------
# Verdant backend-only image for self-host and public backend releases.
# ---------------------------------------------------------------------------

FROM rust:1-bookworm AS builder
WORKDIR /app/server-rs

RUN apt-get update && \
    apt-get install -y --no-install-recommends protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

COPY server-rs/Cargo.toml server-rs/Cargo.lock ./

RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

COPY server-rs/src src
COPY server-rs/build.rs build.rs
COPY proto /app/proto

COPY server-rs/migrations migrations
RUN cd migrations && \
    find . -type f \( -name '*.sql' -o -name 'checksums.sha384' \) -exec sed -i 's/\r$//' {} + && \
    sha384sum -c checksums.sha384

RUN touch src/main.rs
RUN cargo build --release --bin verdant-server

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates ffmpeg && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN groupadd --system verdant && \
    useradd --system --gid verdant --home-dir /app --shell /usr/sbin/nologin verdant && \
    mkdir -p /app/data && \
    chown -R verdant:verdant /app

COPY --from=builder --chown=verdant:verdant /app/server-rs/target/release/verdant-server ./verdant-server
COPY --from=builder --chown=verdant:verdant /app/server-rs/migrations ./migrations

EXPOSE 3001

USER verdant
ENTRYPOINT ["/app/verdant-server"]
