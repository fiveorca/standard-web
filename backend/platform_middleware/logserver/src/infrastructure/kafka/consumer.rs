// ! Kafka Consumer (使用纯 Rust kafka crate)

use crate::common::error::AppError;
use crate::config::KafkaConfig;
use kafka::consumer::{Consumer, FetchOffset, GroupOffsetStorage};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// 单条消费到的日志消息
#[derive(Debug, Clone)]
pub struct RawLogMessage {
    pub event_id: Option<String>,
    pub payload: Vec<u8>,
    pub topic: String,
    pub partition: i32,
    pub offset: i64,
}

impl RawLogMessage {
    pub fn record_key(&self) -> String {
        format!("{}:{}", self.partition, self.offset)
    }
}

/// Kafka 异步 Consumer 包装
///
/// 内部启动一个后台线程做同步 recv()，通过 channel 转发到 async 主循环。
pub struct LogConsumer {
    raw_topic: String,
    consumer_group: String,
    receiver: mpsc::Receiver<RawLogMessage>,
    _join_handle: Option<std::thread::JoinHandle<()>>,
    _inner: Arc<std::sync::Mutex<Option<Consumer>>>,
    brokers: String,
}

impl LogConsumer {
    pub fn new(cfg: &KafkaConfig) -> Result<Self, AppError> {
        Ok(Self {
            raw_topic: cfg.raw_topic.clone(),
            consumer_group: cfg.consumer_group.clone(),
            receiver: {
                // 先放一个占位 receiver，subscribe 时会替换
                let (_tx, rx) = mpsc::channel(1024);
                rx
            },
            _join_handle: None,
            _inner: Arc::new(std::sync::Mutex::new(None)),
            brokers: cfg.brokers.clone(),
        })
    }

    pub fn subscribe(&mut self) -> Result<(), AppError> {
        let brokers = self.brokers.clone();
        let topic = self.raw_topic.clone();
        let group = self.consumer_group.clone();
        let (tx, rx) = mpsc::channel(1024);

        // 初始化 consumer (kafka 0.10 在 Builder 阶段指定 topic partitions)
        let partitions: Vec<i32> = (0..=i32::MAX).collect();
        let consumer = Consumer::from_hosts(vec![brokers.clone()])
            .with_group(group.clone())
            .with_client_id("logserver".to_string())
            .with_fallback_offset(FetchOffset::Earliest)
            .with_offset_storage(Some(GroupOffsetStorage::Kafka))
            .with_topic_partitions(topic.clone(), &partitions)
            .create()
            .map_err(|e| AppError::Kafka(format!("创建 Consumer 失败: {e}")))?;

        info!(topic = %topic, "Kafka Consumer 初始化成功");

        // 替换 receiver
        self.receiver = rx;
        self._inner = Arc::new(std::sync::Mutex::new(Some(consumer)));
        let inner = self._inner.clone();

        // 启动后台读取线程
        let handle = std::thread::Builder::new()
            .name("kafka-consumer".into())
            .spawn(move || {
                loop {
                    let mut guard = inner.lock().unwrap();
                    let consumer = match guard.as_mut() {
                        Some(c) => c,
                        None => {
                            drop(guard);
                            std::thread::sleep(std::time::Duration::from_millis(500));
                            continue;
                        }
                    };

                    match consumer.poll() {
                        Ok(batch) => {
                            drop(guard);
                            for msg_set in batch.iter() {
                                let topic = msg_set.topic().to_string();
                                let partition = msg_set.partition();
                                for msg in msg_set.messages() {
                                    let raw = RawLogMessage {
                                        event_id: if msg.key.is_empty() {
                                            None
                                        } else {
                                            Some(String::from_utf8_lossy(msg.key).to_string())
                                        },
                                        payload: msg.value.to_vec(),
                                        topic: topic.clone(),
                                        partition,
                                        offset: msg.offset,
                                    };
                                    if tx.blocking_send(raw).is_err() {
                                        warn!("channel 关闭，consumer 线程退出");
                                        return;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            drop(guard);
                            error!(?e, "consumer poll 错误，退避重试");
                            std::thread::sleep(std::time::Duration::from_millis(500));
                        }
                    }
                }
            })
            .map_err(|e| AppError::Kafka(format!("启动 consumer 线程失败: {e}")))?;

        self._join_handle = Some(handle);
        Ok(())
    }

    /// 消费单条消息
    pub async fn next(&mut self) -> Result<RawLogMessage, AppError> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| AppError::Kafka("Consumer channel 已关闭".into()))
    }

    /// 手动提交 offset (kafka crate 自动提交)
    pub fn commit(&self, _partition: i32, _offset: i64) -> Result<(), AppError> {
        Ok(())
    }

    pub fn commit_stored(&self) -> Result<(), AppError> {
        Ok(())
    }
}
