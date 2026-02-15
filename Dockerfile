FROM rust:1.85-slim AS builder
WORKDIR /build
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY src src
COPY web web
COPY migrations migrations
COPY config config
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12
WORKDIR /app
COPY --from=builder /build/target/release/alist-encrypt-rs /app/alist-encrypt-rs
EXPOSE 5345
ENTRYPOINT ["/app/alist-encrypt-rs"]
