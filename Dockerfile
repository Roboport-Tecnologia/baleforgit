FROM rust:1.94-bookworm AS builder
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p bale-server-bin \
 && strip target/release/baleforgit-server

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /var/lib/baleforgit-server --create-home bale
COPY --from=builder /src/target/release/baleforgit-server /usr/local/bin/baleforgit-server

USER bale
WORKDIR /var/lib/baleforgit-server
ENV BALE_LISTEN=0.0.0.0:8080 \
    BALE_DATA_ROOT=/var/lib/baleforgit-server/data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/baleforgit-server"]
