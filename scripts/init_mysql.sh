#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

: "${MYSQL_HOST:=127.0.0.1}"
: "${MYSQL_PORT:=3306}"
: "${MYSQL_DB:=alist_encrypt}"
: "${MYSQL_USER:=alist_encrypt}"
: "${MYSQL_PASSWORD:=change_me}"

mysql -h"$MYSQL_HOST" -P"$MYSQL_PORT" -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DB" < migrations/001_init.sql
