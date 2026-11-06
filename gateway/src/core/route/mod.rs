//! 路由编译与匹配。

pub mod table;

use std::sync::Arc;

use crate::config::model::RouteConfig;
use crate::core::filter::{compile_filters, FilterRegistry, GatewayFilter};
use crate::core::predicate::{Predicate, PredicateRequest};
use crate::utils::pattern::PathPattern;

/// 编译后的路由。
pub struct CompiledRoute {
    pub config: RouteConfig,
    pub predicates: Vec<Predicate>,
    pub filters: Vec<Arc<dyn GatewayFilter>>,
    /// 若路由包含 Path 断言，记录其模式用于计算具体程度。
    pub path_pattern: Option<PathPattern>,
    /// 路由具体程度：值越大越具体。
    pub specificity: u32,
}

impl CompiledRoute {
    /// 编译单条路由。
    pub fn compile(config: RouteConfig, registry: &FilterRegistry) -> Result<Self, String> {
        let mut predicates = Vec::with_capacity(config.predicates.len());
        for spec in &config.predicates {
            predicates.push(Predicate::parse(spec)?);
        }
        let filters = compile_filters(registry, &config.filters)?;
        let path_pattern = predicates
            .iter()
            .filter_map(|p| p.path_pattern().cloned())
            .max_by_key(|p| p.specificity());
        let specificity = path_pattern.as_ref().map(|p| p.specificity()).unwrap_or(0);

        Ok(Self {
            config,
            predicates,
            filters,
            path_pattern,
            specificity,
        })
    }

    pub fn id(&self) -> &str {
        &self.config.id
    }

    /// 判断请求是否匹配该路由（所有断言 AND）。
    pub fn matches(&self, req: &PredicateRequest<'_>) -> bool {
        self.predicates.iter().all(|p| p.matches(req))
    }

    /// CORS 预检专用：忽略 Method 断言，其余断言仍须满足。
    pub fn matches_ignoring_method(&self, req: &PredicateRequest<'_>) -> bool {
        self.predicates
            .iter()
            .filter(|p| !matches!(p, Predicate::Method(_)))
            .all(|p| p.matches(req))
    }

    /// 谓词的可读描述，用于管理 API。
    pub fn predicate_descriptions(&self) -> Vec<String> {
        self.predicates.iter().map(|p| p.describe()).collect()
    }
}
