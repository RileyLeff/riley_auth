FROM rust:1.88 AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY crates/riley-auth-core/migrations/ crates/riley-auth-core/migrations/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/* \
    && useradd -m appuser
COPY --from=builder /app/target/release/riley-auth /usr/local/bin/
VOLUME /data
EXPOSE 8081
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8081/health || exit 1
USER appuser
CMD ["riley-auth", "serve"]
