#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

: "${SERVICE_URL:=http://127.0.0.1:5345}"
: "${ADMIN_TOKEN:=}"

echo "[1/5] healthz"
curl -fsS "$SERVICE_URL/healthz" >/dev/null

echo "[2/5] readyz"
curl -fsS "$SERVICE_URL/readyz" >/dev/null

echo "[3/5] metrics"
curl -fsS "$SERVICE_URL/metrics" >/dev/null

echo "[4/5] admin ping"
if [ -n "$ADMIN_TOKEN" ]; then
  curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" "$SERVICE_URL/v2/admin/ping" >/dev/null
else
  curl -fsS "$SERVICE_URL/v2/admin/ping" >/dev/null
fi

echo "[5/5] codec smoke"
if [ -n "$ADMIN_TOKEN" ]; then
  curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'content-type: application/json' \
    -d '{"value":"中文 +-(test)"}' \
    "$SERVICE_URL/v2/admin/codec/encode" >/dev/null
else
  curl -fsS -H 'content-type: application/json' \
    -d '{"value":"中文 +-(test)"}' \
    "$SERVICE_URL/v2/admin/codec/encode" >/dev/null
fi

echo "cutover precheck passed"
