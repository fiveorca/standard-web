//! 已编译的限流策略集合。
//!
//! 与 `gateway-security` 的 `CompiledAuthPolicies` 同构：
//!   - 启动期把 `RateLimitPolicyConfig` 编译为 `CompiledRateLimitPolicy`
//!   - 预构建限流器（TokenBucket 或 FixedWindow）
//!   - 请求路径上只做查表 + 执行，零配置解析开销

use std::collections::HashMap;
use std::sync::Arc;

use gateway_core::{RateLimitAlgorithm, RateLimitPolicyConfig};

use crate::fixed_window::FixedWindowLimiter;
use crate::token_bucket::TokenBucketLimiter;

/// 单个已编译的限流策略。
#[derive(Debug)]
pub struct CompiledRateLimitPolicy {
    /// 策略 ID（与 `RouteConfig::rate_limit_policy_id` 对应）
    pub id: String,
    /// 人类可读名称（日志用）
    pub name: Option<String>,
    /// 是否启用
    pub enabled: bool,
    /// 限流算法（TokenBucket 或 FixedWindow）
    pub algorithm: RateLimitAlgorithm,
    /// 限流器实例（已预构建）
    pub limiter: RateLimiter,
    /// 计数键配置
    pub key: gateway_core::RateLimitKeySpec,
    /// 故障模式（FailClosed / FailOpen）
    pub failure_mode: gateway_core::FailureMode,
}

/// 限流器枚举（TokenBucket 或 FixedWindow）。
#[derive(Debug)]
pub enum RateLimiter {
    /// Token Bucket 算法
    TokenBucket(Arc<TokenBucketLimiter>),
    /// Fixed Window 算法
    FixedWindow(Arc<FixedWindowLimiter>),
}

/// 全部限流策略的编译结果。
#[derive(Debug, Default)]
pub struct CompiledRateLimitPolicies {
    /// 按 ID 索引
    by_id: HashMap<String, CompiledRateLimitPolicy>,
}

impl CompiledRateLimitPolicies {
    /// 编译全部限流策略。
    ///
    /// 参数：
    /// - `configs`：`policies.rate_limit` 段配置
    ///
    /// 返回 `Err` 时**整个集合拒绝加载**。
    pub fn compile(configs: &[RateLimitPolicyConfig]) -> Result<Self, String> {
        let mut by_id = HashMap::with_capacity(configs.len());

        for (idx, config) in configs.iter().enumerate() {
            if config.id.is_empty() {
                return Err(format!("rate_limit[{idx}].id must not be empty"));
            }
            if by_id.contains_key(&config.id) {
                return Err(format!("duplicate rate_limit policy id '{}'", config.id));
            }

            // 编译限流器
            let limiter = match config.algorithm {
                RateLimitAlgorithm::TokenBucket => {
                    let burst = config.burst.unwrap_or(config.rate);
                    RateLimiter::TokenBucket(
                        TokenBucketLimiter::new(config.rate, Some(burst))
                            .map_err(|e| format!("rate_limit[{idx}] ('{}'): {e}", config.id))?,
                    )
                },
                RateLimitAlgorithm::FixedWindow => RateLimiter::FixedWindow(
                    FixedWindowLimiter::new(config.rate, config.window_secs)
                        .map_err(|e| format!("rate_limit[{idx}] ('{}'): {e}", config.id))?,
                ),
            };

            let compiled = CompiledRateLimitPolicy {
                id: config.id.clone(),
                name: config.name.clone(),
                enabled: config.enabled,
                algorithm: config.algorithm,
                limiter,
                key: config.key.clone(),
                failure_mode: config.failure_mode,
            };
            by_id.insert(config.id.clone(), compiled);
        }

        Ok(Self { by_id })
    }

    /// 按 ID 查找策略。
    pub fn get(&self, id: &str) -> Option<&CompiledRateLimitPolicy> {
        self.by_id.get(id)
    }

    /// 策略数量。
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// 是否为空集合。
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_core::{FailureMode, RateLimitKeyKind, RateLimitKeySpec};

    /// 辅助：构造 TokenBucket 策略配置
    fn tb_config(id: &str, rate: u64, burst: Option<u64>) -> RateLimitPolicyConfig {
        RateLimitPolicyConfig {
            id: id.into(),
            name: None,
            enabled: true,
            algorithm: RateLimitAlgorithm::TokenBucket,
            rate,
            burst,
            window_secs: 1,
            key: RateLimitKeySpec {
                kind: RateLimitKeyKind::ClientIp,
                header: None,
            },
            failure_mode: FailureMode::FailClosed,
        }
    }

    /// Token Bucket 策略编译成功
    #[test]
    fn token_bucket_compiles() {
        let configs = vec![tb_config("tb1", 100, Some(200))];
        let policies = CompiledRateLimitPolicies::compile(&configs).expect("should compile");
        assert_eq!(policies.len(), 1);
        let policy = policies.get("tb1").expect("exists");
        assert_eq!(policy.algorithm, RateLimitAlgorithm::TokenBucket);
    }

    /// Fixed Window 策略编译成功
    #[test]
    fn fixed_window_compiles() {
        let mut config = tb_config("fw1", 10, None);
        config.algorithm = RateLimitAlgorithm::FixedWindow;
        config.window_secs = 60;
        let configs = vec![config];
        let policies = CompiledRateLimitPolicies::compile(&configs).expect("should compile");
        let policy = policies.get("fw1").expect("exists");
        assert_eq!(policy.algorithm, RateLimitAlgorithm::FixedWindow);
    }

    /// 重复 ID 必须拒绝
    #[test]
    fn duplicate_ids_are_rejected() {
        let configs = vec![tb_config("dup", 100, None), tb_config("dup", 100, None)];
        assert!(CompiledRateLimitPolicies::compile(&configs).is_err());
    }

    /// rate=0 必须拒绝
    #[test]
    fn zero_rate_is_rejected() {
        let configs = vec![tb_config("bad", 0, None)];
        assert!(CompiledRateLimitPolicies::compile(&configs).is_err());
    }
}
