//! 路由表：基于配置快照的原子更新。
//!
//! 所有请求读取同一个不可变快照（`Arc<RouteSnapshot>`），
//! 路由变更通过 `ArcSwap` 原子替换，正在处理的请求不会读到不完整配置。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use arc_swap::ArcSwap;

use crate::config::model::GatewayConfig;
use crate::core::filter::{compile_filters, FilterRegistry, GatewayFilter};
use crate::core::predicate::PredicateRequest;
use crate::core::route::CompiledRoute;

/// 不可变路由快照。
pub struct RouteSnapshot {
    pub version: u64,
    pub routes: Vec<Arc<CompiledRoute>>,
    pub global_filters: Vec<Arc<dyn GatewayFilter>>,
    pub config: Arc<GatewayConfig>,
    pub hash: String,
    pub loaded_at: SystemTime,
}

impl RouteSnapshot {
    /// 按优先级查找第一个匹配的路由。
    ///
    /// 优先级规则（从高到低）：
    /// 1. `order` 数值更小的优先；
    /// 2. 路径断言更具体的优先；
    /// 3. 路由 ID 字典序更小的优先（保证结果确定）。
    pub fn match_route(&self, req: &PredicateRequest<'_>) -> Option<Arc<CompiledRoute>> {
        self.routes
            .iter()
            .find(|route| route.config.enabled && route.matches(req))
            .cloned()
    }

    /// 忽略 `Method` 断言进行匹配（用于 CORS 预检）。
    pub fn match_route_ignoring_method(
        &self,
        req: &PredicateRequest<'_>,
    ) -> Option<Arc<CompiledRoute>> {
        self.routes
            .iter()
            .find(|route| route.config.enabled && route.matches_ignoring_method(req))
            .cloned()
    }
}

/// 路由表。
pub struct RouteTable {
    current: ArcSwap<RouteSnapshot>,
    version: AtomicU64,
    registry: FilterRegistry,
    update_lock: std::sync::Mutex<()>,
}

impl RouteTable {
    /// 用初始配置构造路由表。
    ///
    /// 注意：该方法假定配置已经通过校验；编译失败会返回错误。
    pub fn new(
        config: GatewayConfig,
        registry: FilterRegistry,
        hash: String,
        version: u64,
    ) -> Result<Self, String> {
        let snapshot = build_snapshot(config, &registry, hash, version)?;
        Ok(Self {
            current: ArcSwap::from_pointee(snapshot),
            version: AtomicU64::new(version),
            registry,
            update_lock: std::sync::Mutex::new(()),
        })
    }

    pub fn snapshot(&self) -> Arc<RouteSnapshot> {
        self.current.load_full()
    }

    /// 原子替换路由配置。若任何路由编译失败，保持旧快照不变。
    pub fn replace(&self, config: GatewayConfig, hash: String) -> Result<u64, String> {
        let _guard = self
            .update_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let next_version = self.version.load(Ordering::SeqCst) + 1;
        let snapshot = build_snapshot(config, &self.registry, hash, next_version)?;
        self.current.store(Arc::new(snapshot));
        self.version.store(next_version, Ordering::SeqCst);
        Ok(next_version)
    }

    /// 原子替换为指定版本（用于集群配置同步）。
    pub fn replace_with_version(
        &self,
        config: GatewayConfig,
        hash: String,
        version: u64,
    ) -> Result<(), String> {
        let _guard = self
            .update_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let snapshot = build_snapshot(config, &self.registry, hash, version)?;
        self.current.store(Arc::new(snapshot));
        self.version.store(version, Ordering::SeqCst);
        Ok(())
    }

    pub fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    pub fn find(&self, id: &str) -> Option<Arc<CompiledRoute>> {
        self.snapshot()
            .routes
            .iter()
            .find(|r| r.id() == id)
            .cloned()
    }
}

fn build_snapshot(
    config: GatewayConfig,
    registry: &FilterRegistry,
    hash: String,
    version: u64,
) -> Result<RouteSnapshot, String> {
    let mut routes = Vec::with_capacity(config.routes.len());
    for route in &config.routes {
        routes.push(Arc::new(CompiledRoute::compile(route.clone(), registry)?));
    }
    routes.sort_by(|a, b| {
        a.config
            .order
            .cmp(&b.config.order)
            .then_with(|| b.specificity.cmp(&a.specificity))
            .then_with(|| a.config.id.cmp(&b.config.id))
    });
    let global_filters = compile_filters(registry, &config.gateway.global_filters)?;
    Ok(RouteSnapshot {
        version,
        routes,
        global_filters,
        config: Arc::new(config),
        hash,
        loaded_at: SystemTime::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::RouteConfig;
    use crate::core::predicate::PredicateRequest;
    use chrono::Utc;
    use http::{HeaderMap, Method};

    fn route(id: &str, order: i32, path: &str) -> RouteConfig {
        serde_yaml::from_str(&format!(
            r#"
id: {id}
order: {order}
uri: http://127.0.0.1:8081
predicates:
  - Path={path}
"#
        ))
        .unwrap()
    }

    fn config(routes: Vec<RouteConfig>) -> GatewayConfig {
        GatewayConfig {
            gateway: Default::default(),
            routes,
        }
    }

    fn table(routes: Vec<RouteConfig>) -> RouteTable {
        RouteTable::new(config(routes), FilterRegistry::builtin(), "h".into(), 0).unwrap()
    }

    fn request<'a>(
        path: &'a str,
        method: &'a Method,
        headers: &'a HeaderMap,
    ) -> PredicateRequest<'a> {
        PredicateRequest {
            method,
            path,
            host: Some("localhost"),
            headers,
            query: None,
            client_ip: None,
            now: Utc::now(),
        }
    }

    #[test]
    fn order_has_priority() {
        let table = table(vec![
            route("generic", 100, "/api/**"),
            route("specific", 10, "/api/users"),
        ]);
        let headers = HeaderMap::new();
        let method = Method::GET;
        let matched = table
            .snapshot()
            .match_route(&request("/api/users", &method, &headers))
            .unwrap();
        assert_eq!(matched.id(), "specific");
    }

    #[test]
    fn specificity_breaks_ties() {
        let table = table(vec![
            route("a-generic", 10, "/api/**"),
            route("b-specific", 10, "/api/users/**"),
        ]);
        let headers = HeaderMap::new();
        let method = Method::GET;
        let matched = table
            .snapshot()
            .match_route(&request("/api/users/1", &method, &headers))
            .unwrap();
        assert_eq!(matched.id(), "b-specific");
    }

    #[test]
    fn dynamic_update_is_atomic() {
        let table = table(vec![route("old", 10, "/old/**")]);
        let headers = HeaderMap::new();
        let method = Method::GET;
        assert!(table
            .snapshot()
            .match_route(&request("/new/x", &method, &headers))
            .is_none());

        table
            .replace(config(vec![route("new", 10, "/new/**")]), "h2".into())
            .unwrap();
        assert!(table
            .snapshot()
            .match_route(&request("/new/x", &method, &headers))
            .is_some());
        assert!(table
            .snapshot()
            .match_route(&request("/old/x", &method, &headers))
            .is_none());
        assert_eq!(table.snapshot().version, 1);
    }

    #[test]
    fn failed_update_keeps_old_snapshot() {
        let table = table(vec![route("old", 10, "/old/**")]);
        let bad: GatewayConfig = serde_yaml::from_str(
            r#"
routes:
  - id: broken
    uri: http://127.0.0.1:1
    predicates:
      - Path=/x
    filters:
      - NotAFilter=1
"#,
        )
        .unwrap();
        assert!(table.replace(bad, "h2".into()).is_err());
        assert_eq!(table.snapshot().routes.len(), 1);
        assert_eq!(table.snapshot().version, 0);
    }
}
