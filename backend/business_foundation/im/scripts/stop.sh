#!/usr/bin/env bash
# 停止 im-service 及其依赖。
# 用法：
#   ./scripts/stop.sh            停止并移除容器（保留数据卷）
#   ./scripts/stop.sh --volumes  同时删除数据卷（会清空数据库与 EMQX 数据）
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="${ENV_FILE:-$ROOT_DIR/.env}"

if ! docker compose version >/dev/null 2>&1; then
  echo "当前 Docker 不支持 'docker compose'，请升级到 Compose V2。" >&2
  exit 1
fi

COMPOSE=(docker compose -f "$ROOT_DIR/docker-compose.yml")
if [ -f "$ENV_FILE" ]; then
  COMPOSE+=(--env-file "$ENV_FILE")
fi

if [ "${1:-}" = "--volumes" ]; then
  echo "==> 停止服务并删除数据卷..."
  "${COMPOSE[@]}" down --volumes --remove-orphans
else
  echo "==> 停止服务（保留数据卷）..."
  "${COMPOSE[@]}" down --remove-orphans
fi
