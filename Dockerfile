FROM rust:1.88 AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY migrations/ migrations/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/riley-auth /usr/local/bin/
VOLUME /data
EXPOSE 8081
CMD ["riley-auth", "serve"]
