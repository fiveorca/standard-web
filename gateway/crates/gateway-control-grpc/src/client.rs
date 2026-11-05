//! 数据面侧 gRPC 同步客户端（Phase 4）。
//!
//! 同步流程（单次）：
//!   1. Heartbeat 询问控制面最新版本
//!   2. 有新版本时 FetchSnapshot
//!   3. 反序列化为 `CompiledSnapshot` 并做 checksum 校验
//!   4. 调用调用方注入的 `apply` 回调（数据面在此处原子替换运行时快照）
//!   5. 上报 ACK / NACK
//!
//! # 可靠性
//!
//! - 控制面不可达时 `sync_once` 返回 `Err`，调用方应忽略并继续使用
//!   本地"最后已知良好配置"（Last Known Good Configuration）；
//! - 应用失败时上报 NACK，控制面记录原因，数据面继续使用旧配置。

use std::future::Future;

use gateway_config::CompiledSnapshot;
use tonic::transport::{Channel, Endpoint};

use crate::pb::config_distribution_client::ConfigDistributionClient;
use crate::pb::{ApplyReport, FetchSnapshotRequest, HeartbeatRequest, RegisterRequest};

/// 一次同步的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// 已是最新版本，无需拉取
    UpToDate {
        /// 控制面当前版本
        version: u64,
    },
    /// 控制面尚未发布任何配置
    NoConfig,
    /// 新快照已成功应用
    Applied {
        /// 已应用版本
        version: u64,
    },
    /// 新快照被拒绝（校验失败或应用失败），数据面继续使用旧配置
    Rejected {
        /// 被拒绝的版本
        version: u64,
        /// 拒绝原因
        message: String,
    },
}

/// 数据面同步客户端（持有长连接 Channel）。
pub struct SyncClient {
    /// 本实例标识
    instance_id: String,
    /// tonic 生成的客户端
    client: ConfigDistributionClient<Channel>,
}

impl SyncClient {
    /// 建立到控制面的连接。
    ///
    /// `endpoint` 需要带协议前缀，例如 `http://127.0.0.1:8092`。
    pub async fn connect(endpoint: &str, instance_id: impl Into<String>) -> Result<Self, String> {
        let endpoint = Endpoint::from_shared(endpoint.to_string())
            .map_err(|e| format!("invalid control-plane endpoint '{endpoint}': {e}"))?;
        let channel = endpoint
            .connect()
            .await
            .map_err(|e| format!("failed to connect control plane: {e}"))?;
        Ok(Self {
            instance_id: instance_id.into(),
            client: ConfigDistributionClient::new(channel),
        })
    }

    /// 向控制面注册实例，返回 `(current_version, checksum)`。
    pub async fn register(
        &mut self,
        gateway_id: &str,
        self_endpoint: &str,
    ) -> Result<(u64, String), String> {
        let response = self
            .client
            .register(RegisterRequest {
                instance_id: self.instance_id.clone(),
                gateway_id: gateway_id.to_string(),
                endpoint: self_endpoint.to_string(),
            })
            .await
            .map_err(|e| format!("register failed: {}", e.message()))?
            .into_inner();
        Ok((response.current_version, response.checksum))
    }

    /// 执行一次完整同步。
    ///
    /// # 参数
    /// - `applied_version`：数据面当前已应用的版本
    /// - `apply`：应用快照的回调；`Ok(())` 表示成功，`Err(msg)` 表示失败
    pub async fn sync_once<F, Fut>(
        &mut self,
        applied_version: u64,
        apply: F,
    ) -> Result<SyncOutcome, String>
    where
        F: FnOnce(CompiledSnapshot) -> Fut,
        Fut: Future<Output = Result<(), String>>,
    {
        // 1. 心跳
        let heartbeat = self
            .client
            .heartbeat(HeartbeatRequest {
                instance_id: self.instance_id.clone(),
                applied_version,
            })
            .await
            .map_err(|e| format!("heartbeat failed: {}", e.message()))?
            .into_inner();

        if !heartbeat.has_update {
            return Ok(SyncOutcome::UpToDate { version: heartbeat.current_version });
        }
        if heartbeat.current_version == 0 {
            return Ok(SyncOutcome::NoConfig);
        }

        // 2. 拉取快照
        let snapshot_response = self
            .client
            .fetch_snapshot(FetchSnapshotRequest { instance_id: self.instance_id.clone() })
            .await
            .map_err(|e| format!("fetch snapshot failed: {}", e.message()))?
            .into_inner();

        if snapshot_response.payload_json.is_empty() {
            return Ok(SyncOutcome::NoConfig);
        }

        // 3. 反序列化 + checksum 校验
        let snapshot: CompiledSnapshot =
            match serde_json::from_str(&snapshot_response.payload_json) {
                Ok(snapshot) => snapshot,
                Err(e) => {
                    let message = format!("invalid snapshot payload: {e}");
                    self.report(snapshot_response.version, false, &message).await;
                    return Ok(SyncOutcome::Rejected {
                        version: snapshot_response.version,
                        message,
                    });
                },
            };

        if !snapshot_response.checksum.is_empty()
            && snapshot.checksum != snapshot_response.checksum
        {
            let message = "snapshot checksum mismatch".to_string();
            self.report(snapshot_response.version, false, &message).await;
            return Ok(SyncOutcome::Rejected { version: snapshot_response.version, message });
        }

        // 4. 应用（数据面原子替换运行时快照）
        let version = snapshot.config_version;
        match apply(snapshot).await {
            Ok(()) => {
                self.report(version, true, "").await;
                Ok(SyncOutcome::Applied { version })
            },
            Err(message) => {
                self.report(version, false, &message).await;
                Ok(SyncOutcome::Rejected { version, message })
            },
        }
    }

    /// 上报应用结果。上报失败只记录日志，不影响数据面继续服务。
    async fn report(&mut self, version: u64, success: bool, message: &str) {
        let report = ApplyReport {
            instance_id: self.instance_id.clone(),
            version,
            success,
            message: message.to_string(),
        };
        if let Err(e) = self.client.report_apply(report).await {
            tracing::warn!(
                version,
                error = e.message(),
                "failed to report snapshot apply result to control plane"
            );
        }
    }
}
