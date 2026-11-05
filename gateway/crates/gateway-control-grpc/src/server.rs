//! 控制面侧 gRPC 服务实现（Phase 4）。
//!
//! 职责：
//!   1. 维护数据面实例注册表（内存态，重启后由数据面重新注册）
//!   2. 心跳时比较版本，告知数据面是否需要拉取新快照
//!   3. 下发最新已发布快照（CompiledSnapshot JSON）
//!   4. 记录 ACK / NACK，NACK 时数据面继续使用旧配置

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use gateway_config::{CompiledSnapshot, ResourceBundle};
use gateway_control_service::ConfigService;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::pb::config_distribution_server::{ConfigDistribution, ConfigDistributionServer};
use crate::pb::{
    ApplyAck, ApplyReport, FetchSnapshotRequest, HeartbeatRequest, HeartbeatResponse,
    RegisterRequest, RegisterResponse, SnapshotResponse,
};

/// 单个数据面实例的运行时状态（仅用于运维展示与故障排查）。
#[derive(Debug, Clone)]
pub struct InstanceState {
    /// 网关集群标识
    pub gateway_id: String,
    /// 数据面自报地址
    pub endpoint: String,
    /// 最近一次成功应用的版本号
    pub applied_version: u64,
    /// 最近一次心跳时间
    pub last_seen: Instant,
    /// 最近一次应用失败原因（成功时为 None）
    pub last_error: Option<String>,
}

/// 控制面 gRPC 服务。
pub struct ConfigDistributionService {
    /// 复用控制面业务服务（版本查询、快照来源）
    service: Arc<ConfigService>,
    /// 实例注册表：instance_id → 状态
    instances: RwLock<HashMap<String, InstanceState>>,
}

impl ConfigDistributionService {
    /// 创建服务实例。
    pub fn new(service: Arc<ConfigService>) -> Self {
        Self { service, instances: RwLock::new(HashMap::new()) }
    }

    /// 读取当前已注册实例快照（供 Admin API / 运维查询使用）。
    pub fn instances(&self) -> Vec<(String, InstanceState)> {
        let guard = self.instances.read().unwrap_or_else(|p| p.into_inner());
        guard.iter().map(|(id, state)| (id.clone(), state.clone())).collect()
    }

    /// 读取当前最新快照。
    ///
    /// # 返回
    /// - `(0, "", None)`：控制面尚未发布任何配置
    /// - `(version, checksum, Some(payload))`：可以下发的快照
    async fn latest_snapshot(&self) -> Result<(u64, String, Option<String>), Status> {
        match self.service.latest_version().await {
            Ok(Some(record)) => {
                // 数据库里存的是 ResourceBundle，需要重新编译成 CompiledSnapshot
                let bundle: ResourceBundle = serde_json::from_value(record.snapshot)
                    .map_err(|e| Status::internal(format!("invalid stored snapshot: {e}")))?;
                let snapshot =
                    CompiledSnapshot::compile(bundle, record.version).map_err(|errors| {
                        Status::failed_precondition(format!(
                            "stored snapshot failed validation: {}",
                            errors.len()
                        ))
                    })?;
                let payload = serde_json::to_string(&snapshot).map_err(|e| {
                    Status::internal(format!("failed to serialize snapshot: {e}"))
                })?;
                Ok((record.version, record.checksum, Some(payload)))
            },
            Ok(None) => Ok((0, String::new(), None)),
            Err(err) => Err(Status::internal(format!("failed to load latest version: {err}"))),
        }
    }

    /// 启动 gRPC 服务并阻塞直至 shutdown。
    pub async fn serve<F>(self, addr: SocketAddr, shutdown: F) -> Result<(), String>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        Server::builder()
            .add_service(ConfigDistributionServer::new(self))
            .serve_with_shutdown(addr, shutdown)
            .await
            .map_err(|e| format!("gRPC server error: {e}"))
    }
}

#[tonic::async_trait]
impl ConfigDistribution for ConfigDistributionService {
    /// 数据面注册：记录实例并返回当前版本，作为后续心跳的基线。
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();
        if req.instance_id.trim().is_empty() {
            return Err(Status::invalid_argument("instance_id must not be empty"));
        }

        let (version, checksum, _payload) = self.latest_snapshot().await?;

        let mut guard = self.instances.write().unwrap_or_else(|p| p.into_inner());
        guard.insert(
            req.instance_id.clone(),
            InstanceState {
                gateway_id: req.gateway_id.clone(),
                endpoint: req.endpoint.clone(),
                applied_version: 0,
                last_seen: Instant::now(),
                last_error: None,
            },
        );
        tracing::info!(
            instance_id = %req.instance_id,
            gateway_id = %req.gateway_id,
            endpoint = %req.endpoint,
            current_version = version,
            "data plane registered"
        );

        Ok(Response::new(RegisterResponse { current_version: version, checksum }))
    }

    /// 心跳：更新最近活跃时间，返回是否有比数据面已应用版本更新的配置。
    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let req = request.into_inner();
        let (current_version, checksum, _payload) = self.latest_snapshot().await?;

        {
            let mut guard = self.instances.write().unwrap_or_else(|p| p.into_inner());
            // 未注册实例直接按注册请求的同一规范接受（重连场景）
            let state = guard.entry(req.instance_id.clone()).or_insert_with(|| InstanceState {
                gateway_id: String::new(),
                endpoint: String::new(),
                applied_version: 0,
                last_seen: Instant::now(),
                last_error: None,
            });
            state.last_seen = Instant::now();
            state.applied_version = req.applied_version;
        }

        Ok(Response::new(HeartbeatResponse {
            current_version,
            has_update: current_version > req.applied_version,
            checksum,
        }))
    }

    /// 下发最新快照。控制面没有已发布配置时返回 version=0 且 payload 为空。
    async fn fetch_snapshot(
        &self,
        request: Request<FetchSnapshotRequest>,
    ) -> Result<Response<SnapshotResponse>, Status> {
        let req = request.into_inner();
        let (version, checksum, payload) = self.latest_snapshot().await?;

        tracing::debug!(instance_id = %req.instance_id, version, "snapshot fetched");

        Ok(Response::new(SnapshotResponse {
            version,
            checksum,
            payload_json: payload.unwrap_or_default(),
        }))
    }

    /// 记录应用结果。NACK 时把失败原因写入实例状态，便于控制面排查。
    async fn report_apply(
        &self,
        request: Request<ApplyReport>,
    ) -> Result<Response<ApplyAck>, Status> {
        let req = request.into_inner();
        let mut guard = self.instances.write().unwrap_or_else(|p| p.into_inner());
        let state = guard.entry(req.instance_id.clone()).or_insert_with(|| InstanceState {
            gateway_id: String::new(),
            endpoint: String::new(),
            applied_version: 0,
            last_seen: Instant::now(),
            last_error: None,
        });
        state.last_seen = Instant::now();

        if req.success {
            state.applied_version = req.version;
            state.last_error = None;
            tracing::info!(
                instance_id = %req.instance_id,
                version = req.version,
                "snapshot applied (ACK)"
            );
        } else {
            state.last_error = Some(req.message.clone());
            tracing::warn!(
                instance_id = %req.instance_id,
                version = req.version,
                message = %req.message,
                "snapshot rejected (NACK), keeping last known good configuration"
            );
        }

        Ok(Response::new(ApplyAck { accepted: true }))
    }
}
