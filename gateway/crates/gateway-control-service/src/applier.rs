//! 快照应用回调。
//!
//! # 为什么用 trait 而不是直接依赖 gateway-runtime
//!
//! 控制面服务（本 crate）需要在发布成功后把快照应用到数据面，但
//! `gateway-control-service` 不依赖 `gateway-runtime`——否则控制面
//! 与数据面会形成紧耦合，独立部署的控制面也必须携带整个运行时。
//!
//! 因此定义 [`SnapshotApplier`] 回调：
//!   - 独立控制面（`apps/gateway-control`）：不注入 applier，或注入
//!     只做本地校验的空实现
//!   - 集成模式（`apps/gateway` integrated）：注入基于 `SnapshotStore`
//!     的实现，实现"不重启网关即可更新配置"

use async_trait::async_trait;
use gateway_config::CompiledSnapshot;

/// 把已发布快照应用到数据面。
///
/// 实现必须是原子替换：失败时旧快照继续生效。
#[async_trait]
pub trait SnapshotApplier: Send + Sync {
    /// 应用快照，返回数据面实际生效的版本号。
    ///
    /// 返回 `Err` 表示应用失败；调用方会把结果记录为 `failed`，
    /// 但**不会**回滚已经保存的配置版本（需求文档第十章）。
    async fn apply(&self, snapshot: &CompiledSnapshot) -> Result<u64, String>;
}
