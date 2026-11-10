#!/bin/bash
# ! Kafka Topic 初始化脚本
#
# 等待 Kafka 就绪后创建 logserver 需要的 topic。
# 用于 docker-compose kafka-init 服务。
set -euo pipefail

BROKERS="${KAFKA_BROKERS:-kafka:9092}"
BOOTSTRAP="${KAFKA_BOOTSTRAP_SERVERS:-kafka:29092}"

TOPICS=(
  "log-events-v1"
  "log-events-v1-dlq"
)

PARTITIONS="${KAFKA_PARTITIONS:-8}"
REPLICATION="${KAFKA_REPLICATION:-1}"
RETENTION_MS="${KAFKA_RETENTION_MS:-1209600000}"

echo "[kafka-init] 等待 Kafka 就绪 (brokers=$BROKERS, bootstrap=$BOOTSTRAP)..."

# 等待 Kafka 可用
for i in $(seq 1 60); do
  if kafka-topics.sh --bootstrap-server "$BOOTSTRAP" --list 2>/dev/null; then
    echo "[kafka-init] Kafka 已就绪"
    break
  fi
  echo "[kafka-init] 等待中 ($i/60)..."
  sleep 5
done

# 创建 topic
for topic in "${TOPICS[@]}"; do
  if kafka-topics.sh --bootstrap-server "$BOOTSTRAP" --describe --topic "$topic" 2>/dev/null; then
    echo "[kafka-init] topic '$topic' 已存在，跳过"
  else
    echo "[kafka-init] 创建 topic '$topic' (partitions=$PARTITIONS, replication=$REPLICATION, retention_ms=$RETENTION_MS)"
    kafka-topics.sh \
      --bootstrap-server "$BOOTSTRAP" \
      --create \
      --if-not-exists \
      --topic "$topic" \
      --partitions "$PARTITIONS" \
      --replication-factor "$REPLICATION" \
      --config retention.ms="$RETENTION_MS"
    echo "[kafka-init] topic '$topic' 创建成功"
  fi
done

echo "[kafka-init] 完成。所有 topic 已就绪。"
kafka-topics.sh --bootstrap-server "$BOOTSTRAP" --list
