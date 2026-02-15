FROM rust:1.85-slim AS builder
WORKDIR /build

# Cache dependencies first. This layer is reused until Cargo.toml/Cargo.lock changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
  && echo 'fn main() {}' > src/main.rs \
  && echo '' > src/lib.rs \
  && cargo build --release --locked

# Real sources
COPY src src
COPY web web
COPY migrations migrations
COPY config config
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12
WORKDIR /app
COPY --from=builder /build/target/release/alist-encrypt-rs /app/alist-encrypt-rs
EXPOSE 5345
ENTRYPOINT ["/app/alist-encrypt-rs"]
