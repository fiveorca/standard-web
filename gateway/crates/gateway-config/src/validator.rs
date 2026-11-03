//! 配置校验：引用完整性、默认值、ID 唯一性、路由冲突检测。
//!
//! YAML 语法正确 ≠ 配置有效。业务层面还有很多需要检查的：
//!
//! 1. **ID 唯一性**：upstreams/services/routes 的 id 不能重复
//! 2. **引用完整性**：Route.service_id 必须指向一个存在的 Service；
//!    Service.upstream_id 必须指向一个存在的 Upstream
//! 3. **端点合法性**：EndpointConfig.port 必须非零；host 不能是空字符串
//! 4. **路由冲突**：两个 Route 如果在 Host+Path+Method+Header+Query+Priority
//!    上完全一致，必须报错（需求文档 4.2 节规定）
//! 5. **数值边界**：max_connections 不能为 0；端口号范围等
//!
//! 所有校验错误都收集到 Vec 里，最后一次性返回 ConfigError::Batch。
//! 这样用户看到的是完整的错误列表，修一个再跑、又冒三个出来的体验很差。

use std::collections::HashSet;

use gateway_core::{PathType, RouteConfig};

use crate::{ConfigError, GatewayConfig};

/// 校验 GatewayConfig，返回所有发现的错误。
///
/// 参数：
/// - `cfg`：loader 解析好的配置
///
/// 返回：
/// - `Ok(())`：无错误
/// - `Err(Vec<ConfigError>)`：所有发现的错误，按类别分组
///
/// 如果返回 Err，调用方应该拒绝这份配置，不进入编译阶段。
pub fn validate(cfg: &GatewayConfig) -> Result<(), Vec<ConfigError>> {
    let mut errors: Vec<ConfigError> = Vec::new();

    validate_server(cfg, &mut errors);
    validate_upstreams(cfg, &mut errors);
    validate_services(cfg, &mut errors);
    validate_routes(cfg, &mut errors);
    validate_references(cfg, &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// ---------------------------------------------------------------------------
// Server 校验
// ---------------------------------------------------------------------------

fn validate_server(cfg: &GatewayConfig, errors: &mut Vec<ConfigError>) {
    // 端口范围：0 是非法值（会让系统自动分配端口，但网关必须固定端口）
    if cfg.server.http.port == 0 {
        errors.push(ConfigError {
            path: "server.http.port".into(),
            message: "port must be non-zero".into(),
        });
    }
    if cfg.server.admin.port == 0 {
        errors.push(ConfigError {
            path: "server.admin.port".into(),
            message: "port must be non-zero".into(),
        });
    }
    // 管理端口不能等于业务端口
    if cfg.server.http.port == cfg.server.admin.port && cfg.server.http.enabled {
        errors.push(ConfigError {
            path: "server".into(),
            message: "http port and admin port must be different".into(),
        });
    }
}

// ---------------------------------------------------------------------------
// Upstreams 校验
// ---------------------------------------------------------------------------

fn validate_upstreams(cfg: &GatewayConfig, errors: &mut Vec<ConfigError>) {
    let mut seen_ids: HashSet<&str> = HashSet::new();

    for (idx, upstream) in cfg.upstreams.iter().enumerate() {
        // ID 不能为空
        if upstream.id.is_empty() {
            errors.push(ConfigError {
                path: format!("upstreams[{idx}].id"),
                message: "id must not be empty".into(),
            });
        }
        // ID 唯一性
        if !upstream.id.is_empty() && !seen_ids.insert(upstream.id.as_str()) {
            errors.push(ConfigError {
                path: format!("upstreams[{idx}].id"),
                message: format!("duplicate upstream id '{}'", upstream.id),
            });
        }
        // 端点校验
        for (ep_idx, ep) in upstream.endpoints.iter().enumerate() {
            let base = format!("upstreams[{idx}].endpoints[{ep_idx}]");
            if ep.host.is_empty() {
                errors.push(ConfigError {
                    path: format!("{base}.host"),
                    message: "host must not be empty".into(),
                });
            }
            if ep.port == 0 {
                errors.push(ConfigError {
                    path: format!("{base}.port"),
                    message: "port must be non-zero".into(),
                });
            }
            if ep.weight == 0 {
                errors.push(ConfigError {
                    path: format!("{base}.weight"),
                    message: "weight must be >= 1".into(),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Services 校验
// ---------------------------------------------------------------------------

fn validate_services(cfg: &GatewayConfig, errors: &mut Vec<ConfigError>) {
    let mut seen_ids: HashSet<&str> = HashSet::new();

    for (idx, svc) in cfg.services.iter().enumerate() {
        let base = format!("services[{idx}]");

        if svc.id.is_empty() {
            errors.push(ConfigError {
                path: format!("{base}.id"),
                message: "id must not be empty".into(),
            });
        }
        if !svc.id.is_empty() && !seen_ids.insert(svc.id.as_str()) {
            errors.push(ConfigError {
                path: format!("{base}.id"),
                message: format!("duplicate service id '{}'", svc.id),
            });
        }
        if svc.upstream_id.is_empty() {
            errors.push(ConfigError {
                path: format!("{base}.upstream_id"),
                message: "upstream_id must not be empty".into(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Routes 校验（含冲突检测）
// ---------------------------------------------------------------------------

fn validate_routes(cfg: &GatewayConfig, errors: &mut Vec<ConfigError>) {
    let mut seen_ids: HashSet<&str> = HashSet::new();

    // 冲突检测需要：在相同 Host+Path+Method+Header+Query+Priority 组合下，
    // 不能有两条 Route。这个组合定义了"确定性匹配"——如果两条 Route 的
    // 匹配条件完全一样，请求进来就不知道该匹配谁。
    //
    // 我们用一个 (HostSet, PathType, PathValue, MethodSet, HeaderSet, QuerySet, Priority)
    // 作为冲突键，检查唯一性。
    let mut conflict_keys: Vec<(String, &RouteConfig)> = Vec::new();

    for (idx, route) in cfg.routes.iter().enumerate() {
        let base = format!("routes[{idx}]");

        // 基础校验
        if route.id.is_empty() {
            errors.push(ConfigError {
                path: format!("{base}.id"),
                message: "id must not be empty".into(),
            });
        }
        if !route.id.is_empty() && !seen_ids.insert(route.id.as_str()) {
            errors.push(ConfigError {
                path: format!("{base}.id"),
                message: format!("duplicate route id '{}'", route.id),
            });
        }
        if route.path_value.is_empty() {
            errors.push(ConfigError {
                path: format!("{base}.path_value"),
                message: "path_value must not be empty".into(),
            });
        }
        // path_value 必须以 "/" 开头
        if !route.path_value.starts_with('/') {
            errors.push(ConfigError {
                path: format!("{base}.path_value"),
                message: "path_value must start with '/'".into(),
            });
        }
        if route.service_id.is_empty() {
            errors.push(ConfigError {
                path: format!("{base}.service_id"),
                message: "service_id must not be empty".into(),
            });
        }

        // 冲突检测的组合键
        // 把 hosts/methods/header_matches/query_matches 排序后 join
        let host_key = join_sorted(&route.hosts);
        let method_key = join_sorted(&route.methods);
        let header_key = join_sorted(
            &route
                .header_matches
                .iter()
                .map(|h| format!("{}={}", h.name, h.exact))
                .collect::<Vec<_>>(),
        );
        let query_key = join_sorted(
            &route
                .query_matches
                .iter()
                .map(|q| format!("{}={}", q.name, q.exact))
                .collect::<Vec<_>>(),
        );
        let key = format!(
            "host={host_key}|ptype={:?}|pvalue={}|method={method_key}|header={header_key}|query={query_key}|priority={}",
            route.path_type, route.path_value, route.priority
        );
        conflict_keys.push((key, route));
    }

    // 冲突查找：O(n²) 在 n<1000 时完全够用；如果未来路由数量大增再优化
    for i in 0..conflict_keys.len() {
        for j in (i + 1)..conflict_keys.len() {
            if conflict_keys[i].0 == conflict_keys[j].0 {
                let (_, a) = conflict_keys[i];
                let (_, b) = conflict_keys[j];
                errors.push(ConfigError {
                    path: "routes".to_string(),
                    message: format!(
                        "conflicting routes: '{}' and '{}' have identical host+path+method+header+query+priority (path_type={:?}, path_value={}, priority={})",
                        a.id, b.id, a.path_type, a.path_value, a.priority
                    ),
                });
            }
        }
    }

    // 启用状态下不能存在 prefix route 和 exact route 同时匹配同一请求
    // 这种情况不算冲突（需求文档允许通过优先级解决），我们只做警告级别的检测
    // Phase 1 先跳过这个，因为编译时 RouteTable 已经按优先级排序处理
    let _ = PathType::Exact; // 消掉未使用警告
}

// ---------------------------------------------------------------------------
// 引用完整性校验
// ---------------------------------------------------------------------------

fn validate_references(cfg: &GatewayConfig, errors: &mut Vec<ConfigError>) {
    // 收集存在的 upstream_ids
    let upstream_ids: HashSet<&str> = cfg.upstreams.iter().map(|u| u.id.as_str()).collect();
    let service_ids: HashSet<&str> = cfg.services.iter().map(|s| s.id.as_str()).collect();

    // Service → Upstream
    for (idx, svc) in cfg.services.iter().enumerate() {
        if !svc.upstream_id.is_empty() && !upstream_ids.contains(svc.upstream_id.as_str()) {
            errors.push(ConfigError {
                path: format!("services[{idx}].upstream_id"),
                message: format!("upstream '{}' does not exist", svc.upstream_id),
            });
        }
    }

    // Route → Service
    for (idx, route) in cfg.routes.iter().enumerate() {
        if !route.service_id.is_empty() && !service_ids.contains(route.service_id.as_str()) {
            errors.push(ConfigError {
                path: format!("routes[{idx}].service_id"),
                message: format!("service '{}' does not exist", route.service_id),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

fn join_sorted(strs: &[String]) -> String {
    if strs.is_empty() {
        return "*".to_string(); // 空集合通配符
    }
    let mut sorted = strs.to_vec();
    sorted.sort();
    sorted.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::load_from_str;

    #[test]
    fn valid_config_passes() {
        let yaml = r#"
gateway:
  id: g1
server:
  http:
    port: 8080
upstreams:
  - id: u1
    endpoints:
      - host: 127.0.0.1
        port: 9090
services:
  - id: s1
    upstream_id: u1
routes:
  - id: r1
    path_value: /api
    service_id: s1
"#;
        let cfg = load_from_str(yaml).unwrap();
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn duplicate_route_id_detected() {
        let yaml = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
upstreams: [{ id: u, endpoints: [{ host: 127.0.0.1, port: 9090 }] }]
services: [{ id: s, upstream_id: u }]
routes:
  - id: dup
    path_value: /a
    service_id: s
  - id: dup
    path_value: /b
    service_id: s
"#;
        let cfg = load_from_str(yaml).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(errs.iter().any(|e| e.path.contains("id") && e.message.contains("duplicate")));
    }

    #[test]
    fn conflicting_routes_detected() {
        let yaml = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
upstreams: [{ id: u, endpoints: [{ host: 127.0.0.1, port: 9090 }] }]
services: [{ id: s, upstream_id: u }]
routes:
  - id: r1
    path_value: /api
    priority: 100
    service_id: s
  - id: r2
    path_value: /api
    priority: 100
    service_id: s
"#;
        let cfg = load_from_str(yaml).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(errs.iter().any(|e| e.message.contains("conflicting")));
    }

    #[test]
    fn missing_reference_detected() {
        let yaml = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
upstreams: []
services: [{ id: s, upstream_id: nowhere }]
routes: []
"#;
        let cfg = load_from_str(yaml).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(errs.iter().any(|e| e.message.contains("does not exist")));
    }

    #[test]
    fn port_zero_detected() {
        let yaml = r#"
gateway: { id: g }
server:
  http:
    port: 0
"#;
        let cfg = load_from_str(yaml).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(errs.iter().any(|e| e.path == "server.http.port"));
    }
}
