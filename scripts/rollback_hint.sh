#!/usr/bin/env bash
set -euo pipefail

echo "rollback steps:"
echo "1) switch ingress back to node-proxy"
echo "2) confirm node-proxy /public and /dav health"
echo "3) keep rust service online for diagnostics"
echo "4) export logs by request_id/trace_id from rust service"
