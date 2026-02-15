# syntax=docker/dockerfile:1.7
FROM rust:1.85-slim AS builder
WORKDIR /build

COPY Cargo.toml Cargo.lock ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
  --mount=type=cache,target=/usr/local/cargo/git/db \
  cargo fetch --locked

COPY src src
COPY web web
COPY migrations migrations
COPY config config
RUN --mount=type=cache,target=/usr/local/cargo/registry \
  --mount=type=cache,target=/usr/local/cargo/git/db \
  --mount=type=cache,target=/build/target \
  cargo build --release --locked

FROM gcr.io/distroless/cc-debian12
WORKDIR /app
COPY --from=builder /build/target/release/alist-encrypt-rs /app/alist-encrypt-rs
EXPOSE 5345
ENTRYPOINT ["/app/alist-encrypt-rs"]
