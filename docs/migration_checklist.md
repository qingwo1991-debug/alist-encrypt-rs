# Migration Checklist

## Pre-migration
- [ ] Configure `config/app.env` with MySQL and upstream.
- [ ] Set `ADMIN_TOKEN`.
- [ ] Run schema init (`AUTO_MIGRATE=true` or `scripts/init_mysql.sh`).
- [ ] Verify baseline endpoints (`/healthz`, `/readyz`, `/metrics`).
- [ ] Validate codec and timeout profile admin APIs.

## Dry-run
- [ ] Replay representative WebDAV and `/d|/p` traffic.
- [ ] Validate timeout logs contain `timeout(stage, xxxms)`.
- [ ] Validate trace/log fields include process/cloud/interface/file tags.
- [ ] Validate CJK/special character filename roundtrip.

## Cutover
- [ ] Freeze write operations.
- [ ] Point ingress to `alist-encrypt-rs`.
- [ ] Run `scripts/cutover_check.sh`.
- [ ] Observe `/metrics` + logs for at least 30 minutes.

## Rollback
- [ ] Run `scripts/rollback_hint.sh` if SLO is violated.
- [ ] Restore ingress to legacy `node-proxy`.
- [ ] Export failing request traces from rust logs.
