# alist-encrypt-rs

Rust rewrite for replacing `node-proxy` with a high-stability/high-performance service.

## Implemented in this slice
- Axum/Tokio service with graceful shutdown.
- Structured lifecycle logs:
  - `request_start`, `upstream_start`, `upstream_first_byte`, `response_commit`, `request_end`.
- Timeout labeling with explicit markers:
  - `timeout(stage, xxxms)` and stage/budget/actual fields.
- Interface-based timeout profiles (control/metadata/small-transfer/large-stream).
- Trace/log context fields for process, cloud drive, interface, filename(raw/encrypted).
- Proxy entrypoints for:
  - `/dav/*`, `/d/*`, `/p/*`.
- WebDAV `PROPFIND` rewrite via structured XML parsing (not plain string replacement).
- Admin timeout profile API:
  - `GET /v2/admin/timeout-profiles/:iface_name`
  - `PUT /v2/admin/timeout-profiles/:iface_name`
- Logging policy API:
  - `GET /v2/admin/logging-policy`
  - `PUT /v2/admin/logging-policy`
- Filename codec validation API:
  - `POST /v2/admin/codec/encode`
  - `POST /v2/admin/codec/decode`
- Metrics endpoint:
  - `GET /metrics`
- Admin web console:
  - `GET /admin`
- MySQL schema bootstrap (`migrations/001_init.sql`) and timeout profile loader.
- Filename normalization/encoding helper for CJK and special symbols.

## Local run
```bash
cd alist-encrypt-rs
cp config/app.env.example config/app.env
cargo run
```

Default listen address: `0.0.0.0:5345`
Set `AUTO_MIGRATE=true` to apply `migrations/001_init.sql` on startup.
Set `ADMIN_TOKEN=<token>` to protect `/v2/admin/*` endpoints with `Authorization: Bearer <token>`.
Runtime performance knobs support HTTP/2, pool, timeout, and body limits (see `config/app.env.example`).
Additional runtime knobs include QoS priority concurrency, strategy-learning rollout, circuit breaker, and metadata prefetch.

## Local tests
```bash
cd alist-encrypt-rs
cargo test
```
or:
```bash
./scripts/run_tests.sh
```

## Format check
```bash
cd alist-encrypt-rs
cargo fmt --all -- --check
```

## Docker
```bash
cd alist-encrypt-rs
docker build -t alist-encrypt-rs:dev -f Dockerfile .
```
or local stack:
```bash
cd alist-encrypt-rs
docker compose up -d
```

## CI outputs
GitHub Actions workflow `.github/workflows/rust_build.yml` runs fmt/clippy/test/build,
creates tar artifact (`alist-encrypt-rs-linux-amd64.tar.gz`) and sha256, and builds multi-arch Docker images.

## API spec
- OpenAPI: `docs/openapi.yaml`
- Migration checklist: `docs/migration_checklist.md`

## Notes
This is a production-oriented skeleton. Full crypto compatibility engine and deeper control-plane business APIs are
staged in `../plan/*.md` and can now be implemented incrementally on this base.
