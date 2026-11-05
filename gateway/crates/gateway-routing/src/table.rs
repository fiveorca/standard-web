//! RouteTable —— 路由表编译与运行时匹配。
//!
//! # 数据结构设计
//!
//! 编译后的路由表结构：
//!
//! ```text
//! RouteTable {
//!     by_host: HashMap<host, HostRoutes>,
//!     default: HostRoutes,   // Host 为空的 Route 放到这里（通配 Host）
//! }
//!
//! HostRoutes {
//!     exact_paths:   BTreeMap<path, Vec<Arc<RouteConfig>>>,  // 按 path 字典序
//!     prefix_paths:  Vec<(path, Vec<Arc<RouteConfig>>)>,     // 按 path 长度降序
//! }
//! ```
//!
//! 为什么 Prefix 要按长度降序？
//! 因为 `/api/users` 比 `/api` 更具体。两个 Prefix Route 都能匹配
//! `/api/users/42` 时，我们优先选更长的那个。然后同一个 path 下
//! 的多个 Route 再按 priority 排序（Priority 降序，大的优先）。
//!
//! # 匹配算法
//!
//! 参考需求文档 4.2 节"路由匹配规则"：
//!
//! ```text
//! 1. 匹配 Host —— 先精确，再 fallback 到通配 Host
//! 2. 匹配 Path 类型及具体程度 —— Exact 先于 Prefix
//! 3. 匹配 Method —— Route.methods 为空表示通配
//! 4. 匹配 Header —— 所有 header_matches 都必须满足
//! 5. 匹配 Query —— 所有 query_matches 都必须满足
//! 6. 匹配 Priority —— 相同条件下 priority 大的优先
//! ```
//!
//! 一旦某个 Host 桶内找到了 Method 不支持的 Host+Path 组合，我们会
//! 记录下允许的 Method 列表，返回 MethodNotAllowed（而不是直接继续
//! 尝试其他 Host 桶）。这是 HTTP 语义规定的：URL 存在但 Method 不支持 → 405。

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use gateway_core::RouteConfig;

// ---------------------------------------------------------------------------
// 匹配结果
// ---------------------------------------------------------------------------

/// 路由匹配结果。
///
/// 三种变体对应三种 HTTP 状态码：
///   - `Matched(Arc<RouteConfig>)` → 匹配成功 → 继续代理
///   - `MethodNotAllowed(Vec<String>)` → 405，列出该 URL 支持的 Method
///   - `NoMatch` → 404
#[derive(Debug, Clone)]
pub enum MatchResult {
    /// 成功匹配到一条 Route。内部 RouteConfig 是 Arc，多个并发请求共享同一份数据。
    Matched(Arc<RouteConfig>),
    /// Host+Path 精确匹配成功，但 Method 不在 Route 的 methods 列表里。
    /// 返回该 URL 上所有可用 Route 的 methods 并集，让客户端知道可以用什么 Method。
    MethodNotAllowed { allowed_methods: Vec<String> },
    /// 没有任何 Route 匹配（Host+Path+Method 全都没命中）
    NoMatch,
}

// ---------------------------------------------------------------------------
// RouteTable 主体
// ---------------------------------------------------------------------------

/// 编译后的不可变路由表。
///
/// 创建方式：`RouteTable::compile(&[RouteConfig])`。
/// 运行时通过 `route_table.resolve(host, path, method, headers, query)` 查询。
#[derive(Debug, Default)]
pub struct RouteTable {
    /// Host → 路由组。空 Host Route 会被放到 `default` 字段。
    by_host: HashMap<String, HostRoutes>,
    /// Host 为空或 "*" 的通配 Host 路由组
    default: HostRoutes,
}

/// 单个 Host 下的路由集合。
#[derive(Debug, Default)]
struct HostRoutes {
    /// Exact Path 路由，key 是 path_value，value 是该 path 下所有 Route
    /// （按 priority 降序排列）。用 BTreeMap 是因为它保持 key 排序，
    /// 但我们实际上只做精确查找（contains_key），不用区间查询，
    /// HashMap 也可以；这里选 BTreeMap 主要是语义上的"有序集合"。
    exact_paths: BTreeMap<String, Vec<Arc<RouteConfig>>>,
    /// Prefix Path 路由。按 path 长度降序排列——更长的前缀更具体。
    /// 每个 path 下的 Route 也按 priority 降序排列。
    prefix_paths: Vec<PrefixGroup>,
}

#[derive(Debug)]
struct PrefixGroup {
    /// 前缀路径，例如 "/api/users"
    path: String,
    /// 该前缀下所有 Route，按 priority 降序排列
    routes: Vec<Arc<RouteConfig>>,
}

impl RouteTable {
    /// 从 RouteConfig 列表编译路由表。
    ///
    /// 参数：
    /// - `routes`：所有 RouteConfig（enabled 和 disabled 都可以传进来，
    ///   disabled 的会被过滤掉）
    ///
    /// 调用前必须已经通过了 `gateway-config::validate` 的冲突检测——
    /// 编译阶段假设输入是合法的。如果这里再发现非法配置，直接 panic 或返回 Err。
    pub fn compile(routes: &[RouteConfig]) -> Self {
        let mut table = RouteTable::default();

        for route in routes {
            // disabled 的 Route 不进入路由表
            if !route.enabled {
                continue;
            }
            // Phase 7：生命周期过滤
            // Draft（草稿）与 Retired（已下线）不对外提供服务；
            // Deprecated 仍进入路由表，由 Runtime 在响应头标记弃用。
            if !route.lifecycle.is_servable() {
                continue;
            }
            let arc = Arc::new(route.clone());

            // Host 处理
            // route.hosts 是一个列表。每个 Host 都要注册同一条 Route。
            // 如果列表为空（没有限制 Host），则注册到 default（通配）
            let hosts: Vec<String> = if route.hosts.is_empty() {
                vec![String::new()] // 空字符串代表通配 Host
            } else {
                route.hosts.clone()
            };

            for host in hosts {
                let host_routes = if host.is_empty() {
                    &mut table.default
                } else {
                    table.by_host.entry(host).or_default()
                };
                host_routes.add(arc.clone());
            }
        }

        // 排序：每个 Path 组内按 priority 降序排
        table.sort();
        table
    }

    /// 对编译好的路由表做最终排序。
    ///
    /// - exact_paths 内每个 path 下的 Route 按 priority 降序
    /// - prefix_paths 按 path 长度降序（长前缀优先匹配）
    /// - 每个 prefix path 内按 priority 降序
    fn sort(&mut self) {
        for host_routes in self.by_host.values_mut() {
            host_routes.sort_groups();
        }
        self.default.sort_groups();
    }

    /// 查询路由匹配。
    ///
    /// # 参数
    /// - `host`：请求头 Host 字段（小写处理）
    /// - `path`：请求 URL 的 path 部分（不含 query）
    /// - `method`：HTTP Method（大写，例如 `"GET"`）
    /// - `headers`：请求头。Route 的 header_matches 会从这里取值比较
    /// - `query`：URL 的 query 字符串（不含 `?`），用于 Route 的 query_matches
    pub fn resolve(
        &self,
        host: &str,
        path: &str,
        method: &str,
        headers: &http::HeaderMap,
        query: Option<&str>,
    ) -> MatchResult {
        // 按需求文档规定的顺序：先精确 Host，再 fallback 通配 Host
        let host_candidates: Vec<&HostRoutes> = {
            let mut cands = Vec::new();
            // 精确 Host（host 非空时尝试）
            if !host.is_empty() {
                if let Some(hr) = self.by_host.get(host) {
                    cands.push(hr);
                }
            }
            // 通配 Host（默认匹配）——总是加入 fallback
            cands.push(&self.default);
            cands
        };

        // 用于 405：累计所有尝试过的 Host+Path 组合上可用的 Method
        let mut method_candidates: Vec<String> = Vec::new();

        for host_routes in host_candidates {
            // 1. 尝试 Exact Path（优先级最高）
            if let Some(routes) = host_routes.exact_paths.get(path) {
                if let Some(result) =
                    self.try_match_group(routes, method, headers, query, &mut method_candidates)
                {
                    return result;
                }
            }

            // 2. 尝试 Prefix Path
            //    把所有 prefix group 里的路由打平成一个 Vec，
            //    按 (priority desc, path_length desc) 统一排序
            //    priority 最高 → 优先尝试；同 priority 时更长的 path 优先（更具体）
            let mut all_prefix_routes: Vec<&Arc<RouteConfig>> = Vec::new();
            for group in &host_routes.prefix_paths {
                for r in &group.routes {
                    if path.starts_with(&group.path) {
                        all_prefix_routes.push(r);
                    }
                }
            }
            all_prefix_routes.sort_by(|a, b| {
                b.priority
                    .cmp(&a.priority)
                    .then_with(|| b.path_value.len().cmp(&a.path_value.len()))
            });
            // 逐个尝试匹配
            for route in all_prefix_routes {
                if let Some(result) = self.try_match_group(
                    std::slice::from_ref(route),
                    method,
                    headers,
                    query,
                    &mut method_candidates,
                ) {
                    return result;
                }
            }
        }

        // 如果 method_candidates 非空，说明我们找到了 Host+Path 匹配，
        // 但 Method 不对 → 405
        if !method_candidates.is_empty() {
            return MatchResult::MethodNotAllowed {
                allowed_methods: method_candidates,
            };
        }

        MatchResult::NoMatch
    }

    /// 在一组 Route 中尝试找到第一个完全匹配的。
    ///
    /// 内部会按 priority 降序遍历每条 Route，依次检查 Method、Header、Query 条件。
    /// 第一个全部满足的 Route 就是匹配结果。
    ///
    /// 如果没有 Route 能匹配（Method 都不对），会把遇到的所有 Route.methods
    /// 合并到 method_candidates 里，用于最终返回 405 的 allowed_methods。
    fn try_match_group(
        &self,
        routes: &[Arc<RouteConfig>],
        method: &str,
        headers: &http::HeaderMap,
        query: Option<&str>,
        method_candidates: &mut Vec<String>,
    ) -> Option<MatchResult> {
        for route in routes {
            // 检查 Method
            if !route.methods.is_empty() && !route.methods.iter().any(|m| m == method) {
                // Method 不匹配 → 把 Route 上允许的 Method 记下来
                for m in &route.methods {
                    if !method_candidates.contains(m) {
                        method_candidates.push(m.clone());
                    }
                }
                continue; // 继续尝试同组的下一条 Route（可能允许这个 Method）
            }

            // 检查 Header（全部满足才算匹配）
            if !self.check_headers(&route.header_matches, headers) {
                continue;
            }

            // 检查 Query
            if !self.check_query(&route.query_matches, query) {
                continue;
            }

            // 全部条件满足 → 匹配成功
            return Some(MatchResult::Matched(route.clone()));
        }

        None
    }

    /// 检查所有 header_matches 条件是否都满足。
    ///
    /// header_matches 为空时直接返回 true（该 Route 不限制 Header）。
    /// 有条件时，每个条件都必须满足（AND 语义）。
    fn check_headers(
        &self,
        header_matches: &[gateway_core::HeaderMatch],
        headers: &http::HeaderMap,
    ) -> bool {
        for hm in header_matches {
            // Header 名大小写不敏感：http::HeaderMap::get 已经处理了。
            // 但 hm.name 可能是 "X-API-Version" 这种大小写混合的，
            // header_map.get() 接受 &str，自动大小写不敏感匹配。
            let Some(value) = headers.get(hm.name.as_str()) else {
                return false;
            };
            // Header value 也是字节，需要比较字节序列（避免编码问题）
            if value.as_bytes() != hm.exact.as_bytes() {
                return false;
            }
        }
        true
    }

    /// 检查所有 query_matches 条件是否都满足。
    fn check_query(&self, query_matches: &[gateway_core::QueryMatch], query: Option<&str>) -> bool {
        if query_matches.is_empty() {
            return true; // 不限制 Query
        }
        let Some(query_str) = query else {
            return false; // Route 有 query 条件但请求没带 query
        };
        // 手工解析 query：按 & 分割，每个再按 = 分割
        // 不引入 url 或 form_urlencoded crate，保持轻量
        let pairs: Vec<(&str, &str)> = query_str
            .split('&')
            .filter_map(|kv| {
                let (k, v) = kv.split_once('=')?;
                Some((k, v))
            })
            .collect();

        for qm in query_matches {
            let found = pairs.iter().any(|(k, v)| k == &qm.name && v == &qm.exact);
            if !found {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// HostRoutes 方法
// ---------------------------------------------------------------------------

impl HostRoutes {
    fn add(&mut self, route: Arc<RouteConfig>) {
        match route.path_type {
            gateway_core::PathType::Exact => {
                self.exact_paths.entry(route.path_value.clone()).or_default().push(route);
            },
            gateway_core::PathType::Prefix => {
                // 找到 path 相同的组，或创建新组
                if let Some(group) =
                    self.prefix_paths.iter_mut().find(|g| g.path == route.path_value)
                {
                    group.routes.push(route);
                } else {
                    self.prefix_paths.push(PrefixGroup {
                        path: route.path_value.clone(),
                        routes: vec![route],
                    });
                }
            },
        }
    }

    fn sort_groups(&mut self) {
        // exact：每个 path 内按 priority 降序
        for routes in self.exact_paths.values_mut() {
            routes.sort_by_key(|a| std::cmp::Reverse(a.priority));
        }
        // prefix：先按 path 长度降序，再按 path 字典序（稳定排序保证确定性）
        self.prefix_paths
            .sort_by(|a, b| b.path.len().cmp(&a.path.len()).then_with(|| a.path.cmp(&b.path)));
        // 每个 prefix group 内按 priority 降序
        for group in self.prefix_paths.iter_mut() {
            group.routes.sort_by_key(|a| std::cmp::Reverse(a.priority));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_core::{PathType, RouteConfig};

    /// 构造 RouteConfig 的小工具
    fn route(
        id: &str,
        hosts: &[&str],
        path: &str,
        ptype: PathType,
        methods: &[&str],
        priority: i32,
    ) -> RouteConfig {
        RouteConfig {
            id: id.into(),
            name: Some(id.into()),
            // Phase 7：测试使用公共租户 + 已发布状态
            tenant_id: None,
            lifecycle: gateway_core::LifecycleStatus::Published,
            enabled: true,
            priority,
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
            methods: methods.iter().map(|s| s.to_string()).collect(),
            path_type: ptype,
            path_value: path.into(),
            header_matches: vec![],
            query_matches: vec![],
            service_id: "svc".into(),
            timeout_policy_id: None,
            auth_policy_id: None,
            rate_limit_policy_id: None,
            retry_policy_id: None,
            // P2.1 新增的策略引用字段，测试中不使用
            circuit_breaker_policy_id: None,
            cors_policy_id: None,
            path_rewrite: None,
            // Phase 6 字段：测试中不使用灰度/镜像
            traffic_split: None,
            mirror: None,
            // Phase 7：测试不使用 WAF / 配额
            waf_policy_id: None,
            quota_policy_id: None,
            request_transform_id: None,
            response_transform_id: None,
        }
    }

    #[test]
    fn exact_match() {
        let table = RouteTable::compile(&[route(
            "r1",
            &[],
            "/api/users/42",
            PathType::Exact,
            &["GET"],
            100,
        )]);
        let h = http::HeaderMap::new();
        let r = table.resolve("", "/api/users/42", "GET", &h, None);
        assert!(matches!(r, MatchResult::Matched(_)));
    }

    #[test]
    fn exact_does_not_match_prefix() {
        let table = RouteTable::compile(&[route(
            "r1",
            &[],
            "/api/users",
            PathType::Exact,
            &["GET"],
            100,
        )]);
        let h = http::HeaderMap::new();
        let r = table.resolve("", "/api/users/42", "GET", &h, None);
        assert!(matches!(r, MatchResult::NoMatch));
    }

    #[test]
    fn prefix_match() {
        let table = RouteTable::compile(&[route(
            "r1",
            &[],
            "/api/users",
            PathType::Prefix,
            &["GET"],
            100,
        )]);
        let h = http::HeaderMap::new();
        let r = table.resolve("", "/api/users/42", "GET", &h, None);
        assert!(matches!(r, MatchResult::Matched(_)));
    }

    #[test]
    fn exact_over_prefix() {
        // 同 Host+Path 下，Exact 应该优先于 Prefix
        let table = RouteTable::compile(&[
            route("r-prefix", &[], "/api", PathType::Prefix, &["GET"], 100),
            route("r-exact", &[], "/api", PathType::Exact, &["GET"], 100),
        ]);
        let h = http::HeaderMap::new();
        let r = table.resolve("", "/api", "GET", &h, None);
        match r {
            MatchResult::Matched(arc) => assert_eq!(arc.id, "r-exact"),
            _ => panic!("expected match"),
        }
    }

    #[test]
    fn prefix_longer_wins() {
        // "/api/users" 前缀应比 "/api" 更优先
        let table = RouteTable::compile(&[
            route("r-short", &[], "/api", PathType::Prefix, &["GET"], 100),
            route("r-long", &[], "/api/users", PathType::Prefix, &["GET"], 100),
        ]);
        let h = http::HeaderMap::new();
        let r = table.resolve("", "/api/users/42", "GET", &h, None);
        match r {
            MatchResult::Matched(arc) => assert_eq!(arc.id, "r-long"),
            _ => panic!("expected match"),
        }
    }

    #[test]
    fn priority_wins_over_prefix_length() {
        // 更高 priority 应该先匹配（即使 path 更短）
        let table = RouteTable::compile(&[
            route("r-low", &[], "/api/users", PathType::Prefix, &["GET"], 10),
            route("r-high", &[], "/api", PathType::Prefix, &["GET"], 100),
        ]);
        let h = http::HeaderMap::new();
        let r = table.resolve("", "/api/users/42", "GET", &h, None);
        match r {
            MatchResult::Matched(arc) => assert_eq!(arc.id, "r-high"),
            _ => panic!("expected match"),
        }
    }

    #[test]
    fn method_not_allowed() {
        let table = RouteTable::compile(&[route(
            "r1",
            &[],
            "/api/users",
            PathType::Exact,
            &["GET"],
            100,
        )]);
        let h = http::HeaderMap::new();
        let r = table.resolve("", "/api/users", "POST", &h, None);
        match r {
            MatchResult::MethodNotAllowed { allowed_methods } => {
                assert!(allowed_methods.iter().any(|m| m == "GET"));
            },
            _ => panic!("expected 405"),
        }
    }

    #[test]
    fn host_matches() {
        let table = RouteTable::compile(&[
            route("r-a", &["a.example.com"], "/", PathType::Prefix, &["GET"], 100),
            route("r-default", &[], "/", PathType::Prefix, &["GET"], 100),
        ]);
        let h = http::HeaderMap::new();
        let r1 = table.resolve("a.example.com", "/", "GET", &h, None);
        match r1 {
            MatchResult::Matched(arc) => assert_eq!(arc.id, "r-a"),
            _ => panic!("expected match"),
        }
        let r2 = table.resolve("other.com", "/", "GET", &h, None);
        match r2 {
            MatchResult::Matched(arc) => assert_eq!(arc.id, "r-default"),
            _ => panic!("expected match"),
        }
    }

    #[test]
    fn disabled_route_skipped() {
        let mut r = route("disabled", &[], "/x", PathType::Exact, &["GET"], 100);
        r.enabled = false;
        let table = RouteTable::compile(&[r]);
        let h = http::HeaderMap::new();
        assert!(matches!(table.resolve("", "/x", "GET", &h, None), MatchResult::NoMatch));
    }

    #[test]
    fn empty_compile_returns_nomatch() {
        let table = RouteTable::compile(&[]);
        let h = http::HeaderMap::new();
        assert!(matches!(table.resolve("", "/", "GET", &h, None), MatchResult::NoMatch));
    }
}
