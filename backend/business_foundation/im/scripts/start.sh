#!/usr/bin/env bash
# 启动 im-service 及其依赖（PostgreSQL、EMQX）。
# 用法：./scripts/start.sh [服务名...]
#   ./scripts/start.sh                  启动全部服务
#   ./scripts/start.sh im-service       仅重建并启动 im-service
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="${ENV_FILE:-$ROOT_DIR/.env}"

if ! command -v docker >/dev/null 2>&1; then
  echo "未找到 docker 命令，请先安装 Docker Engine / Docker Desktop。" >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "当前 Docker 不支持 'docker compose'，请升级到 Compose V2。" >&2
  exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
  echo "警告：未找到 $ENV_FILE，将使用 docker-compose.yml 中的开发默认值。"
  echo "      建议先执行：cp .env.example .env"
fi

COMPOSE=(docker compose -f "$ROOT_DIR/docker-compose.yml")
if [ -f "$ENV_FILE" ]; then
  COMPOSE+=(--env-file "$ENV_FILE")
fi

echo "==> 构建并启动服务..."
"${COMPOSE[@]}" up -d --build "$@"

echo "==> 当前状态："
"${COMPOSE[@]}" ps

read_env() {
  local key="$1" fallback="$2" value=""
  if [ -f "$ENV_FILE" ]; then
    value="$(grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- || true)"
  fi
  echo "${value:-$fallback}"
}

HTTP_PORT="$(read_env IM_HTTP_PORT 8080)"
GRPC_PORT="$(read_env IM_GRPC_PORT 9090)"
DASHBOARD_PORT="$(read_env EMQX_DASHBOARD_PORT 18083)"

echo
echo "等待 im-service 就绪（最多 120 秒）..."

for _ in $(seq 1 60); do
  if curl -fsS "http://localhost:${HTTP_PORT}/actuator/health/readiness" >/dev/null 2>&1; then
    echo "im-service 已就绪。"
    echo "  HTTP   : http://localhost:${HTTP_PORT}"
    echo "  Swagger: http://localhost:${HTTP_PORT}/docs"
    echo "  Health : http://localhost:${HTTP_PORT}/actuator/health"
    echo "  gRPC   : localhost:${GRPC_PORT}"
    echo "  EMQX   : http://localhost:${DASHBOARD_PORT}"
    exit 0
  fi
  sleep 2
done

echo "im-service 未在预期时间内就绪，请执行以下命令查看日志：" >&2
echo "  docker compose logs -f im-service" >&2
exit 1
