//! integrated 模式的控制面装配。
//!
//! 该模式把控制面 Admin API 挂载到网关自身的管理端口，并与数据面共享
//! 同一个 [`SnapshotStore`]：
//!
//! ```text
//! POST /api/admin/v1/config/publish
//!         │
//!         ├─ 校验 + 编译 + 落库（config_versions / audit_logs）
//!         └─ RuntimeApplier → SnapshotStore::apply（原子热更新）
//! ```
//!
//! 因此发布成功后**无需重启网关**即可生效；应用失败时旧配置继续服务。

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use gateway_config::CompiledSnapshot;
use gateway_control_api::{build_admin_router, AdminAuth, AdminState, Role};
use gateway_control_service::{ConfigService, SnapshotApplier};
use gateway_runtime::{Runtime, SnapshotStore};
use gateway_storage::{connect_and_migrate, PoolSettings, PostgresRepository, SharedRepository};

/// 把控制面快照应用到数据面的回调实现。
struct RuntimeApplier {
    /// 与数据面共享的快照存储
    store: Arc<SnapshotStore>,
}

#[async_trait]
impl SnapshotApplier for RuntimeApplier {
    async fn apply(&self, snapshot: &CompiledSnapshot) -> Result<u64, String> {
        // SnapshotStore::apply 是同步原子操作：校验版本单调后一次性替换
        self.store.apply(snapshot).map_err(|e| e.to_string())
    }
}

/// 构建 integrated 模式的管理路由。
///
/// # 环境变量
/// - `GATEWAY_DATABASE_URL`：控制面数据库（必填）
/// - `GATEWAY_ADMIN_TOKENS`：管理员 token 清单（必填）
/// - `GATEWAY_VIEWER_TOKENS`：只读 token 清单（可选）
/// - `GATEWAY_INSTANCE_ID`：实例标识（可选，写入发布记录）
pub async fn build_integrated_router(runtime: &Arc<Runtime>) -> Result<axum::Router> {
    // 控制面必须挂在管理端口上，否则无法访问
    if !runtime.admin_enabled() {
        return Err(anyhow!(
            "integrated mode requires server.admin.enabled = true in the gateway config"
        ));
    }

    let database_url = std::env::var("GATEWAY_DATABASE_URL")
        .map_err(|_| anyhow!("GATEWAY_DATABASE_URL is required in integrated mode"))?;

    let pool = connect_and_migrate(&database_url, PoolSettings::default())
        .await
        .context("failed to connect control-plane database")?;
    let repo: SharedRepository = Arc::new(PostgresRepository::new(pool));

    // 认证：至少一个 admin token；没有 token 时拒绝启动控制面而不是开放访问
    let mut auth = AdminAuth::empty();
    if let Ok(spec) = std::env::var("GATEWAY_ADMIN_TOKENS") {
        auth.add_spec(&spec, "admin", Role::Admin);
    }
    if let Ok(spec) = std::env::var("GATEWAY_VIEWER_TOKENS") {
        auth.add_spec(&spec, "viewer", Role::Viewer);
    }
    if !auth.is_configured() {
        return Err(anyhow!(
            "GATEWAY_ADMIN_TOKENS is required in integrated mode"
        ));
    }

    let instance_id =
        std::env::var("GATEWAY_INSTANCE_ID").unwrap_or_else(|_| "gateway-integrated".to_string());
    let service = ConfigService::with_applier(
        repo,
        Arc::new(RuntimeApplier {
            store: runtime.snapshot_store(),
        }),
        instance_id,
    );

    Ok(build_admin_router(AdminState::new(service, auth)))
}
