// ! 可观测性 (tracing + prometheus)

use once_cell::sync::Lazy;
use prometheus::{Counter, Encoder, Histogram, HistogramOpts, Registry, TextEncoder};

static REGISTRY: Lazy<Registry> = Lazy::new(|| Registry::new());

// ===== 指标定义 =====

pub static GRPC_INGEST_BATCH_TOTAL: Lazy<Counter> = Lazy::new(|| {
    Counter::new("logserver_grpc_ingest_batch_total", "gRPC IngestBatch 总请求数")
        .expect("metric")
});
pub static GRPC_ACCEPTED_TOTAL: Lazy<Counter> = Lazy::new(|| {
    Counter::new("logserver_grpc_accepted_total", "gRPC 接受的日志数量").expect("metric")
});
pub static GRPC_REJECTED_TOTAL: Lazy<Counter> = Lazy::new(|| {
    Counter::new("logserver_grpc_rejected_total", "gRPC 拒绝的日志数量").expect("metric")
});

pub static KAFKA_SEND_TOTAL: Lazy<Counter> = Lazy::new(|| {
    Counter::new("logserver_kafka_send_total", "Kafka Producer 发送消息数").expect("metric")
});
pub static KAFKA_SEND_FAILED_TOTAL: Lazy<Counter> = Lazy::new(|| {
    Counter::new("logserver_kafka_send_failed_total", "Kafka Producer 发送失败数").expect("metric")
});

pub static KAFKA_CONSUME_TOTAL: Lazy<Counter> = Lazy::new(|| {
    Counter::new("logserver_kafka_consume_total", "Kafka Consumer 消费消息数").expect("metric")
});
pub static DLQ_TOTAL: Lazy<Counter> =
    Lazy::new(|| Counter::new("logserver_dlq_total", "进入 DLQ 的消息数").expect("metric"));

pub static CLICKHOUSE_INSERT_ROWS_TOTAL: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "logserver_clickhouse_insert_rows_total",
        "ClickHouse 插入总行数",
    )
    .expect("metric")
});

pub static CLICKHOUSE_INSERT_BATCH_DURATION_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    Histogram::with_opts(HistogramOpts::new(
        "logserver_clickhouse_insert_batch_duration_seconds",
        "ClickHouse 批量写入耗时",
    ))
    .expect("histogram")
});

pub static CLICKHOUSE_QUERY_DURATION_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    Histogram::with_opts(HistogramOpts::new(
        "logserver_clickhouse_query_duration_seconds",
        "ClickHouse 查询耗时",
    ))
    .expect("histogram")
});

/// 注册所有 metrics 到全局 registry
pub fn register_all() {
    let reg = &*REGISTRY;
    reg.register(Box::new(GRPC_INGEST_BATCH_TOTAL.clone())).ok();
    reg.register(Box::new(GRPC_ACCEPTED_TOTAL.clone())).ok();
    reg.register(Box::new(GRPC_REJECTED_TOTAL.clone())).ok();
    reg.register(Box::new(KAFKA_SEND_TOTAL.clone())).ok();
    reg.register(Box::new(KAFKA_SEND_FAILED_TOTAL.clone())).ok();
    reg.register(Box::new(KAFKA_CONSUME_TOTAL.clone())).ok();
    reg.register(Box::new(DLQ_TOTAL.clone())).ok();
    reg.register(Box::new(CLICKHOUSE_INSERT_ROWS_TOTAL.clone()))
        .ok();
    reg.register(Box::new(CLICKHOUSE_INSERT_BATCH_DURATION_SECONDS.clone()))
        .ok();
    reg.register(Box::new(CLICKHOUSE_QUERY_DURATION_SECONDS.clone()))
        .ok();
}

pub fn encode() -> String {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buf = Vec::new();
    encoder.encode(&metric_families, &mut buf).unwrap_or_default();
    String::from_utf8_lossy(&buf).to_string()
}

/// 初始化 tracing subscriber
pub fn init_tracing() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(false);

    let filter_layer = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .try_init()
        .ok();
}
