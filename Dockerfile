FROM rust:1.88-bookworm AS builder
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p xet-server-bin \
 && strip target/release/xet-server

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /var/lib/xet-server --create-home xet
COPY --from=builder /src/target/release/xet-server /usr/local/bin/xet-server

USER xet
WORKDIR /var/lib/xet-server
ENV XET_LISTEN=0.0.0.0:8080 \
    XET_DATA_ROOT=/var/lib/xet-server/data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/xet-server"]
