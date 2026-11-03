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
//! 6. **策略校验（P2.1）**：策略字段的安全约束（算法白名单、幂等重试、
//!    CORS 通配+凭据冲突、Header 注入防护）以及 Route → Policy 引用完整性
//!
//! 所有校验错误都收集到 Vec 里，最后一次性返回 ConfigError::Batch。
//! 这样用户看到的是完整的错误列表，修一个再跑、又冒三个出来的体验很差。

use std::collections::HashSet;
use std::net::IpAddr;

use gateway_core::{AuthPolicySpec, PathType, RateLimitAlgorithm, RateLimitKeyKind, RouteConfig};

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
    validate_policies(cfg, &mut errors);
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
// Policies 校验（P2.1 新增）
// ---------------------------------------------------------------------------

/// 校验所有策略配置段。
///
/// 校验分两类：
///   1. **结构/安全约束**：每个策略自身的字段是否合法、是否违反安全底线
///   2. **引用完整性**：由 [`validate_references`] 单独处理（Route → Policy）
///
/// 每个错误都带精确路径（如 `policies.auth[0].algorithms`），
/// 便于运维直接定位到 YAML 的行。
fn validate_policies(cfg: &GatewayConfig, errors: &mut Vec<ConfigError>) {
    validate_auth_policies(cfg, errors);
    validate_rate_limit_policies(cfg, errors);
    validate_timeout_policies(cfg, errors);
    validate_retry_policies(cfg, errors);
    validate_circuit_breaker_policies(cfg, errors);
    validate_cors_policies(cfg, errors);
    validate_transform_policies(
        &cfg.policies.request_transform,
        "policies.request_transform",
        errors,
    );
    validate_transform_policies(
        &cfg.policies.response_transform,
        "policies.response_transform",
        errors,
    );
}

/// 校验某一段内策略 ID 的唯一性与非空性。
///
/// `ids`：该段所有策略的 ID（按配置顺序）
/// `section`：YAML 中的段路径，用于错误定位
fn validate_unique_policy_ids(ids: &[&str], section: &str, errors: &mut Vec<ConfigError>) {
    let mut seen: HashSet<&str> = HashSet::new();
    for (idx, id) in ids.iter().enumerate() {
        if id.is_empty() {
            errors.push(ConfigError {
                path: format!("{section}[{idx}].id"),
                message: "id must not be empty".into(),
            });
        } else if !seen.insert(*id) {
            errors.push(ConfigError {
                path: format!("{section}[{idx}].id"),
                message: format!("duplicate policy id '{id}'"),
            });
        }
    }
}

/// 校验鉴权策略。
///
/// 安全要点：
///   - IP 名单不能为空（空 allowlist 会拒绝全部流量、空 denylist 形同虚设，
///     两者基本都是配置错误）
///   - JWT 算法白名单不能为空；静态密钥方案下 secret 必填
///   - JWT 的 leeway 必须收敛在合理范围，避免过期 token 长期可用
fn validate_auth_policies(cfg: &GatewayConfig, errors: &mut Vec<ConfigError>) {
    let section = "policies.auth";
    let ids: Vec<&str> = cfg.policies.auth.iter().map(|p| p.id.as_str()).collect();
    validate_unique_policy_ids(&ids, section, errors);

    for (idx, policy) in cfg.policies.auth.iter().enumerate() {
        let base = format!("{section}[{idx}]");

        match &policy.spec {
            // ---- IP 名单类 ----
            AuthPolicySpec::IpAllowlist { cidrs } | AuthPolicySpec::IpDenylist { cidrs } => {
                if cidrs.is_empty() {
                    errors.push(ConfigError {
                        path: format!("{base}.cidrs"),
                        message: "cidrs must not be empty (empty list make the policy meaningless)"
                            .into(),
                    });
                }
                for (cidr_idx, cidr) in cidrs.iter().enumerate() {
                    if !is_valid_cidr_or_ip(cidr) {
                        errors.push(ConfigError {
                            path: format!("{base}.cidrs[{cidr_idx}]"),
                            message: format!(
                                "invalid CIDR/IP '{cidr}' (expected e.g. '10.0.0.0/8' or '192.168.1.5')"
                            ),
                        });
                    }
                }
            },

            // ---- Basic ----
            AuthPolicySpec::Basic { credentials } => {
                if credentials.is_empty() {
                    errors.push(ConfigError {
                        path: format!("{base}.credentials"),
                        message: "credentials must not be empty".into(),
                    });
                }
                for (cred_idx, cred) in credentials.iter().enumerate() {
                    if cred.username.is_empty() {
                        errors.push(ConfigError {
                            path: format!("{base}.credentials[{cred_idx}].username"),
                            message: "username must not be empty".into(),
                        });
                    }
                    if cred.password.is_empty() {
                        errors.push(ConfigError {
                            path: format!("{base}.credentials[{cred_idx}].password"),
                            message: "password must not be empty".into(),
                        });
                    }
                }
            },

            // ---- API Key ----
            AuthPolicySpec::ApiKey {
                keys,
                header_name,
                query_param,
            } => {
                if keys.is_empty() {
                    errors.push(ConfigError {
                        path: format!("{base}.keys"),
                        message: "keys must not be empty".into(),
                    });
                }
                for (key_idx, key) in keys.iter().enumerate() {
                    if key.key.is_empty() {
                        errors.push(ConfigError {
                            path: format!("{base}.keys[{key_idx}].key"),
                            message: "key must not be empty".into(),
                        });
                    }
                }
                if !is_valid_header_name(header_name) {
                    errors.push(ConfigError {
                        path: format!("{base}.header_name"),
                        message: format!("invalid header name '{header_name}'"),
                    });
                }
                if let Some(qp) = query_param {
                    if qp.is_empty() {
                        errors.push(ConfigError {
                            path: format!("{base}.query_param"),
                            message: "query_param must not be empty when configured".into(),
                        });
                    }
                }
            },

            // ---- JWT（静态密钥 + 算法白名单）----
            AuthPolicySpec::Jwt {
                secret,
                algorithms,
                leeway_secs,
                header_name,
                query_param,
                validate_exp,
                ..
            } => {
                // 算法白名单不能为空：空白名单意味着任何 (包括伪造的) 算法都无处校验
                if algorithms.is_empty() {
                    errors.push(ConfigError {
                        path: format!("{base}.algorithms"),
                        message: "algorithms must not be empty (explicit whitelist is required)"
                            .into(),
                    });
                }
                // 静态密钥方案下，HMAC 必须提供 non-empty secret
                match secret {
                    None => errors.push(ConfigError {
                        path: format!("{base}.secret"),
                        message: "secret is required for HS256/HS384/HS512".into(),
                    }),
                    Some(s) if s.is_empty() => errors.push(ConfigError {
                        path: format!("{base}.secret"),
                        message: "secret must not be empty".into(),
                    }),
                    // HMAC-SHA256 的安全强度下限：短于 32 字节的密钥容易离线暴力破解
                    Some(s) if s.len() < 32 => errors.push(ConfigError {
                        path: format!("{base}.secret"),
                        message: "secret should be at least 32 bytes for HS256 security".into(),
                    }),
                    Some(_) => {},
                }
                // leeway 过大会让已过期 Token 长时间仍可用
                if *leeway_secs > 300 {
                    errors.push(ConfigError {
                        path: format!("{base}.leeway_secs"),
                        message: "leeway_secs must be <= 300".into(),
                    });
                }
                if !is_valid_header_name(header_name) {
                    errors.push(ConfigError {
                        path: format!("{base}.header_name"),
                        message: format!("invalid header name '{header_name}'"),
                    });
                }
                if let Some(qp) = query_param {
                    if qp.is_empty() {
                        errors.push(ConfigError {
                            path: format!("{base}.query_param"),
                            message: "query_param must not be empty when configured".into(),
                        });
                    }
                }
                // 关闭 exp 校验是非常危险的配置（Token 永不过期），直接拒绝
                if !*validate_exp {
                    errors.push(ConfigError {
                        path: format!("{base}.validate_exp"),
                        message: "validate_exp must not be false (non-expiring tokens are unsafe)"
                            .into(),
                    });
                }
            },
        }
    }
}

/// 校验限流策略。
fn validate_rate_limit_policies(cfg: &GatewayConfig, errors: &mut Vec<ConfigError>) {
    let section = "policies.rate_limit";
    let ids: Vec<&str> = cfg.policies.rate_limit.iter().map(|p| p.id.as_str()).collect();
    validate_unique_policy_ids(&ids, section, errors);

    for (idx, policy) in cfg.policies.rate_limit.iter().enumerate() {
        let base = format!("{section}[{idx}]");

        // 速率必须为正：0 会导致所有请求被拒（或除零），两种都不是好结果
        if policy.rate == 0 {
            errors.push(ConfigError {
                path: format!("{base}.rate"),
                message: "rate must be >= 1".into(),
            });
        }

        match policy.algorithm {
            RateLimitAlgorithm::TokenBucket => {
                // 桶容量为 0 会让桶永远空着，请求全被拒
                if let Some(burst) = policy.burst {
                    if burst == 0 {
                        errors.push(ConfigError {
                            path: format!("{base}.burst"),
                            message: "burst must be >= 1".into(),
                        });
                    }
                }
            },
            RateLimitAlgorithm::FixedWindow => {
                // 窗口长度为 0 无法定义计数周期
                if policy.window_secs == 0 {
                    errors.push(ConfigError {
                        path: format!("{base}.window_secs"),
                        message: "window_secs must be >= 1 for fixed_window".into(),
                    });
                }
            },
        }

        // header 维度限流必须指定 header 名称
        if policy.key.kind == RateLimitKeyKind::Header {
            match &policy.key.header {
                None => errors.push(ConfigError {
                    path: format!("{base}.key.header"),
                    message: "header is required when key.kind = header".into(),
                }),
                Some(name) if !is_valid_header_name(name) => errors.push(ConfigError {
                    path: format!("{base}.key.header"),
                    message: format!("invalid header name '{name}'"),
                }),
                Some(_) => {},
            }
        }
    }
}

/// 校验超时策略。
fn validate_timeout_policies(cfg: &GatewayConfig, errors: &mut Vec<ConfigError>) {
    let section = "policies.timeout";
    let ids: Vec<&str> = cfg.policies.timeout.iter().map(|p| p.id.as_str()).collect();
    validate_unique_policy_ids(&ids, section, errors);

    for (idx, policy) in cfg.policies.timeout.iter().enumerate() {
        let base = format!("{section}[{idx}]");

        if policy.connect_timeout_ms == 0 {
            errors.push(ConfigError {
                path: format!("{base}.connect_timeout_ms"),
                message: "connect_timeout_ms must be >= 1".into(),
            });
        }
        if policy.request_timeout_ms == 0 {
            errors.push(ConfigError {
                path: format!("{base}.request_timeout_ms"),
                message: "request_timeout_ms must be >= 1".into(),
            });
        }
        // 首包超时必须覆盖连接超时，否则连接超时永远不会先触发，配置形同虚设
        if policy.request_timeout_ms != 0
            && policy.connect_timeout_ms != 0
            && policy.request_timeout_ms < policy.connect_timeout_ms
        {
            errors.push(ConfigError {
                path: format!("{base}.request_timeout_ms"),
                message: format!(
                    "request_timeout_ms ({}) must be >= connect_timeout_ms ({})",
                    policy.request_timeout_ms, policy.connect_timeout_ms
                ),
            });
        }
        if let Some(idle) = policy.idle_timeout_ms {
            if idle == 0 {
                errors.push(ConfigError {
                    path: format!("{base}.idle_timeout_ms"),
                    message: "idle_timeout_ms must be >= 1 when configured".into(),
                });
            }
        }
    }
}

/// 校验重试策略。
///
/// 核心约束是需求文档的"不允许不安全重试"：
/// `retry_methods` 只能是幂等方法，POST/PATCH 之类必须被拒绝。
fn validate_retry_policies(cfg: &GatewayConfig, errors: &mut Vec<ConfigError>) {
    let section = "policies.retry";
    let ids: Vec<&str> = cfg.policies.retry.iter().map(|p| p.id.as_str()).collect();
    validate_unique_policy_ids(&ids, section, errors);

    for (idx, policy) in cfg.policies.retry.iter().enumerate() {
        let base = format!("{section}[{idx}]");

        // max_attempts 含首次，因此最小为 1（等于不重试）
        if policy.max_attempts == 0 {
            errors.push(ConfigError {
                path: format!("{base}.max_attempts"),
                message: "max_attempts must be >= 1 (value includes the first attempt)".into(),
            });
        }

        // 幂等方法白名单：RFC 7231 定义的幂等方法
        for (m_idx, method) in policy.retry_methods.iter().enumerate() {
            if !is_idempotent_method(method) {
                errors.push(ConfigError {
                    path: format!("{base}.retry_methods[{m_idx}]"),
                    message: format!(
                        "method '{method}' is not idempotent; retrying it may duplicate side effects (allowed: GET/HEAD/OPTIONS/PUT/DELETE/TRACE)"
                    ),
                });
            }
        }

        // 状态码范围必须合法
        for (s_idx, status) in policy.retry_statuses.iter().enumerate() {
            if !(100..=599).contains(status) {
                errors.push(ConfigError {
                    path: format!("{base}.retry_statuses[{s_idx}]"),
                    message: format!("invalid HTTP status code {status}"),
                });
            }
        }

        // 退避参数：重试>1 次时延迟必须有效
        if policy.max_attempts > 1 {
            if policy.backoff.base_delay_ms == 0 {
                errors.push(ConfigError {
                    path: format!("{base}.backoff.base_delay_ms"),
                    message: "base_delay_ms must be >= 1 when retries are enabled".into(),
                });
            }
            if policy.backoff.max_delay_ms != 0
                && policy.backoff.max_delay_ms < policy.backoff.base_delay_ms
            {
                errors.push(ConfigError {
                    path: format!("{base}.backoff.max_delay_ms"),
                    message: format!(
                        "max_delay_ms ({}) must be >= base_delay_ms ({})",
                        policy.backoff.max_delay_ms, policy.backoff.base_delay_ms
                    ),
                });
            }
        }

        // 重试需要缓冲请求体，上限为 0 意味着任何带 body 的请求都无法重试
        if policy.max_body_bytes == 0 {
            errors.push(ConfigError {
                path: format!("{base}.max_body_bytes"),
                message: "max_body_bytes must be >= 1".into(),
            });
        }
    }
}

/// 校验熔断策略。
fn validate_circuit_breaker_policies(cfg: &GatewayConfig, errors: &mut Vec<ConfigError>) {
    let section = "policies.circuit_breaker";
    let ids: Vec<&str> = cfg.policies.circuit_breaker.iter().map(|p| p.id.as_str()).collect();
    validate_unique_policy_ids(&ids, section, errors);

    for (idx, policy) in cfg.policies.circuit_breaker.iter().enumerate() {
        let base = format!("{section}[{idx}]");

        if policy.failure_threshold == 0 {
            errors.push(ConfigError {
                path: format!("{base}.failure_threshold"),
                message: "failure_threshold must be >= 1".into(),
            });
        }
        if policy.success_threshold == 0 {
            errors.push(ConfigError {
                path: format!("{base}.success_threshold"),
                message: "success_threshold must be >= 1".into(),
            });
        }
        if policy.open_duration_secs == 0 {
            errors.push(ConfigError {
                path: format!("{base}.open_duration_secs"),
                message: "open_duration_secs must be >= 1".into(),
            });
        }
        for (s_idx, status) in policy.failure_statuses.iter().enumerate() {
            if !(100..=599).contains(status) {
                errors.push(ConfigError {
                    path: format!("{base}.failure_statuses[{s_idx}]"),
                    message: format!("invalid HTTP status code {status}"),
                });
            }
        }
    }
}

/// 校验 CORS 策略。
///
/// 核心安全约束：`allow_credentials = true` 不能与 `allow_origins = ["*"]` 组合。
fn validate_cors_policies(cfg: &GatewayConfig, errors: &mut Vec<ConfigError>) {
    let section = "policies.cors";
    let ids: Vec<&str> = cfg.policies.cors.iter().map(|p| p.id.as_str()).collect();
    validate_unique_policy_ids(&ids, section, errors);

    for (idx, policy) in cfg.policies.cors.iter().enumerate() {
        let base = format!("{section}[{idx}]");

        if policy.allow_origins.is_empty() {
            errors.push(ConfigError {
                path: format!("{base}.allow_origins"),
                message: "allow_origins must not be empty (use [\"*\"] for a public API)".into(),
            });
        }

        for (o_idx, origin) in policy.allow_origins.iter().enumerate() {
            if !is_valid_origin(origin) {
                errors.push(ConfigError {
                    path: format!("{base}.allow_origins[{o_idx}]"),
                    message: format!(
                        "invalid origin '{origin}' (expected '*' or 'http(s)://host[:port]')"
                    ),
                });
            }
        }

        // 浏览器规范禁止 "*" 与 credentials 组合；
        // 允许该组合等于允许任意站点携带用户凭据发起跨域请求
        if policy.allow_credentials && policy.allow_origins.iter().any(|o| o == "*") {
            errors.push(ConfigError {
                path: format!("{base}.allow_credentials"),
                message: "allow_credentials cannot be true when allow_origins contains '*'".into(),
            });
        }

        if policy.allow_methods.is_empty() {
            errors.push(ConfigError {
                path: format!("{base}.allow_methods"),
                message: "allow_methods must not be empty".into(),
            });
        }
        for (m_idx, method) in policy.allow_methods.iter().enumerate() {
            if !is_valid_token(method) {
                errors.push(ConfigError {
                    path: format!("{base}.allow_methods[{m_idx}]"),
                    message: format!("invalid HTTP method '{method}'"),
                });
            }
        }

        for (h_idx, header) in policy.allow_headers.iter().enumerate() {
            if header != "*" && !is_valid_header_name(header) {
                errors.push(ConfigError {
                    path: format!("{base}.allow_headers[{h_idx}]"),
                    message: format!("invalid header name '{header}'"),
                });
            }
        }
        for (h_idx, header) in policy.expose_headers.iter().enumerate() {
            if !is_valid_header_name(header) {
                errors.push(ConfigError {
                    path: format!("{base}.expose_headers[{h_idx}]"),
                    message: format!("invalid header name '{header}'"),
                });
            }
        }
    }
}

/// 校验 Header 转换策略（请求方向与响应方向共用）。
///
/// 请求/响应方向都调用同一个校验函数，只是 `section` 路径不同。
fn validate_transform_policies(
    policies: &[gateway_core::TransformPolicyConfig],
    section: &str,
    errors: &mut Vec<ConfigError>,
) {
    let ids: Vec<&str> = policies.iter().map(|p| p.id.as_str()).collect();
    validate_unique_policy_ids(&ids, section, errors);

    for (idx, policy) in policies.iter().enumerate() {
        let base = format!("{section}[{idx}]");

        for (h_idx, name) in policy.remove_headers.iter().enumerate() {
            if !is_valid_header_name(name) {
                errors.push(ConfigError {
                    path: format!("{base}.remove_headers[{h_idx}]"),
                    message: format!("invalid header name '{name}'"),
                });
            }
        }

        // Header 注入防护：值里出现 CR/LF/NUL 会允许攻击者拆分响应头
        for (kind, entries) in [
            ("set_headers", &policy.set_headers),
            ("add_headers", &policy.add_headers),
        ] {
            for (h_idx, entry) in entries.iter().enumerate() {
                if !is_valid_header_name(&entry.name) {
                    errors.push(ConfigError {
                        path: format!("{base}.{kind}[{h_idx}].name"),
                        message: format!("invalid header name '{}'", entry.name),
                    });
                }
                if !is_valid_header_value(&entry.value) {
                    errors.push(ConfigError {
                        path: format!("{base}.{kind}[{h_idx}].value"),
                        message: "header value must not contain CR/LF/NUL (header injection risk)"
                            .into(),
                    });
                }
            }
        }
    }
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

    // -----------------------------------------------------------------------
    // Route → Policy 引用完整性（P2.1 新增）
    // -----------------------------------------------------------------------
    // 每个策略段独立收集 ID 集合。Route 的引用字段是强类型的
    // （auth_policy_id 只能指向 policies.auth 段），因此只需按段检查。
    let auth_ids: HashSet<&str> = cfg.policies.auth.iter().map(|p| p.id.as_str()).collect();
    let rate_limit_ids: HashSet<&str> =
        cfg.policies.rate_limit.iter().map(|p| p.id.as_str()).collect();
    let timeout_ids: HashSet<&str> = cfg.policies.timeout.iter().map(|p| p.id.as_str()).collect();
    let retry_ids: HashSet<&str> = cfg.policies.retry.iter().map(|p| p.id.as_str()).collect();
    let breaker_ids: HashSet<&str> =
        cfg.policies.circuit_breaker.iter().map(|p| p.id.as_str()).collect();
    let cors_ids: HashSet<&str> = cfg.policies.cors.iter().map(|p| p.id.as_str()).collect();
    let req_transform_ids: HashSet<&str> =
        cfg.policies.request_transform.iter().map(|p| p.id.as_str()).collect();
    let resp_transform_ids: HashSet<&str> =
        cfg.policies.response_transform.iter().map(|p| p.id.as_str()).collect();

    // 逐条 Route 检查 8 类策略引用（None 表示未引用，直接通过）
    for (idx, route) in cfg.routes.iter().enumerate() {
        check_policy_ref(
            route.auth_policy_id.as_ref(),
            &auth_ids,
            format!("routes[{idx}].auth_policy_id"),
            "policies.auth",
            errors,
        );
        check_policy_ref(
            route.rate_limit_policy_id.as_ref(),
            &rate_limit_ids,
            format!("routes[{idx}].rate_limit_policy_id"),
            "policies.rate_limit",
            errors,
        );
        check_policy_ref(
            route.timeout_policy_id.as_ref(),
            &timeout_ids,
            format!("routes[{idx}].timeout_policy_id"),
            "policies.timeout",
            errors,
        );
        check_policy_ref(
            route.retry_policy_id.as_ref(),
            &retry_ids,
            format!("routes[{idx}].retry_policy_id"),
            "policies.retry",
            errors,
        );
        check_policy_ref(
            route.circuit_breaker_policy_id.as_ref(),
            &breaker_ids,
            format!("routes[{idx}].circuit_breaker_policy_id"),
            "policies.circuit_breaker",
            errors,
        );
        check_policy_ref(
            route.cors_policy_id.as_ref(),
            &cors_ids,
            format!("routes[{idx}].cors_policy_id"),
            "policies.cors",
            errors,
        );
        check_policy_ref(
            route.request_transform_id.as_ref(),
            &req_transform_ids,
            format!("routes[{idx}].request_transform_id"),
            "policies.request_transform",
            errors,
        );
        check_policy_ref(
            route.response_transform_id.as_ref(),
            &resp_transform_ids,
            format!("routes[{idx}].response_transform_id"),
            "policies.response_transform",
            errors,
        );
    }
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

/// 检查一个可选策略引用是否存在。
///
/// 参数：
/// - `reference`：Route 上的引用字段值（None 表示未引用，直接通过）
/// - `known`：目标策略段已有的 ID 集合
/// - `path`：错误路径（如 `routes[0].auth_policy_id`）
/// - `section`：目标段名（用于错误消息）
/// - `errors`：错误收集器
fn check_policy_ref(
    reference: Option<&String>,
    known: &HashSet<&str>,
    path: String,
    section: &str,
    errors: &mut Vec<ConfigError>,
) {
    if let Some(id) = reference {
        // 空字符串视为"未配置"，与 None 语义一致（路由上留空不报错）
        if !id.is_empty() && !known.contains(id.as_str()) {
            errors.push(ConfigError {
                path,
                message: format!("policy '{id}' does not exist in {section}"),
            });
        }
    }
}

/// 校验 CIDR 或单个 IP。
///
/// 支持两种写法：
///   - `10.0.0.0/8`（CIDR：IP + 前缀长度）
///   - `192.168.1.5`（单个 IP，等价于 `/32` 或 `/128`）
///
/// 前缀长度上限：IPv4 为 32，IPv6 为 128。
fn is_valid_cidr_or_ip(text: &str) -> bool {
    match text.split_once('/') {
        // CIDR 形态
        Some((ip_part, prefix_part)) => {
            let Ok(addr) = ip_part.parse::<IpAddr>() else {
                return false;
            };
            let Ok(prefix) = prefix_part.parse::<u8>() else {
                return false;
            };
            match addr {
                IpAddr::V4(_) => prefix <= 32,
                IpAddr::V6(_) => prefix <= 128,
            }
        },
        // 单个 IP 形态
        None => text.parse::<IpAddr>().is_ok(),
    }
}

/// 校验 HTTP Header 名称是否合法（RFC 7230 token 字符集）。
///
/// 允许的字符：`!#$%&'*+-.^_`|~` + 数字 + 字母。
/// 拒绝空格、冒号、控制字符等会破坏报文结构的字符。
fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            matches!(b,
                b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-'
                | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
                | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
        })
}

/// 校验 HTTP Header 值是否安全（禁止 CR/LF/NUL）。
///
/// 这是防 Header 注入的底线：值里若含 `\r\n`，攻击者可以
/// 在响应中注入额外的 header 甚至 body，造成响应拆分攻击。
fn is_valid_header_value(value: &str) -> bool {
    !value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

/// 校验 CORS Origin 是否合法。
///
/// 允许的形态：
///   - `*`（通配）
///   - `http://host[:port]` / `https://host[:port]`
///
/// 注意 Origin 不应包含路径（浏览器规范中 origin = scheme + host + port）。
fn is_valid_origin(origin: &str) -> bool {
    if origin == "*" {
        return true;
    }
    let rest = origin.strip_prefix("http://").or_else(|| origin.strip_prefix("https://"));
    match rest {
        Some(host_part) => {
            !host_part.is_empty() && !host_part.contains('/') && !host_part.contains(' ')
        },
        None => false,
    }
}

/// 校验 HTTP Method 是否为合法 token。
///
/// Method 同样遵循 RFC 7230 token 字符集。
fn is_valid_token(text: &str) -> bool {
    is_valid_header_name(text)
}

/// 判断 Method 是否为幂等方法（可以安全重试）。
///
/// 依据 RFC 7231 §4.2.2：
///   - GET / HEAD / OPTIONS / TRACE：天然幂等
///   - PUT / DELETE：定义上幂等（多次执行的副作用与一次相同）
///   - POST / PATCH / CONNECT：**非幂等**，重试可能重复业务副作用
fn is_idempotent_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS" | "TRACE" | "PUT" | "DELETE"
    )
}

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

    // -----------------------------------------------------------------------
    // P2.1 策略校验
    // -----------------------------------------------------------------------

    /// 合法策略配置应通过校验（覆盖 8 类策略段）
    #[test]
    fn valid_policies_pass() {
        let yaml = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
upstreams: [{ id: u, endpoints: [{ host: 127.0.0.1, port: 9090 }] }]
services: [{ id: s, upstream_id: u }]
policies:
  auth:
    - id: jwt-main
      type: jwt
      secret: "0123456789abcdef0123456789abcdef"
      algorithms: [HS256]
      issuer: gateway
  rate_limit:
    - id: rl
      algorithm: token_bucket
      rate: 100
      burst: 200
  timeout:
    - id: to
  retry:
    - id: rt
      max_attempts: 3
  circuit_breaker:
    - id: cb
  cors:
    - id: c1
      allow_origins: [https://app.example.com]
  request_transform:
    - id: rq
      remove_headers: [X-Internal]
  response_transform:
    - id: rs
      add_headers: [{ name: X-Gateway, value: standard-web }]
routes:
  - id: r1
    path_value: /api
    service_id: s
    auth_policy_id: jwt-main
    rate_limit_policy_id: rl
    timeout_policy_id: to
    retry_policy_id: rt
    circuit_breaker_policy_id: cb
    cors_policy_id: c1
    request_transform_id: rq
    response_transform_id: rs
"#;
        let cfg = load_from_str(yaml).unwrap();
        assert!(validate(&cfg).is_ok(), "errors: {:?}", validate(&cfg).err());
    }

    /// JWT：算法白名单为空 / 缺少 secret 都必须报错
    #[test]
    fn jwt_policy_requires_whitelist_and_secret() {
        let yaml = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
policies:
  auth:
    - id: jwt-bad
      type: jwt
"#;
        let cfg = load_from_str(yaml).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(
            errs.iter().any(|e| e.path.contains("algorithms")),
            "expected algorithms error, got {errs:?}"
        );
        assert!(
            errs.iter().any(|e| e.path.contains("secret")),
            "expected secret error, got {errs:?}"
        );
    }

    /// JWT：短密钥（< 32 字节）必须被拒绝
    #[test]
    fn jwt_short_secret_rejected() {
        let yaml = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
policies:
  auth:
    - id: jwt-short
      type: jwt
      secret: "short"
      algorithms: [HS256]
"#;
        let cfg = load_from_str(yaml).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(errs.iter().any(|e| e.path.contains("secret")));
    }

    /// 重试：非幂等方法（POST）必须被拒绝
    #[test]
    fn retry_non_idempotent_method_rejected() {
        let yaml = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
policies:
  retry:
    - id: rt-bad
      retry_methods: [POST]
"#;
        let cfg = load_from_str(yaml).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(
            errs.iter().any(|e| e.message.contains("not idempotent")),
            "expected idempotency error, got {errs:?}"
        );
    }

    /// CORS：通配 origin + credentials 组合必须被拒绝
    #[test]
    fn cors_wildcard_with_credentials_rejected() {
        let yaml = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
policies:
  cors:
    - id: c-bad
      allow_origins: ["*"]
      allow_credentials: true
"#;
        let cfg = load_from_str(yaml).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(errs.iter().any(|e| e.path.contains("allow_credentials")));
    }

    /// 策略 ID 在段内必须唯一
    #[test]
    fn duplicate_policy_id_detected() {
        let yaml = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
policies:
  timeout:
    - id: dup
    - id: dup
"#;
        let cfg = load_from_str(yaml).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(errs.iter().any(|e| e.message.contains("duplicate policy id")));
    }

    /// Route 引用了不存在的策略必须报错
    #[test]
    fn missing_policy_reference_detected() {
        let yaml = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
upstreams: [{ id: u, endpoints: [{ host: 127.0.0.1, port: 9090 }] }]
services: [{ id: s, upstream_id: u }]
routes:
  - id: r1
    path_value: /api
    service_id: s
    auth_policy_id: not-exist
"#;
        let cfg = load_from_str(yaml).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(
            errs.iter()
                .any(|e| e.path.contains("auth_policy_id") && e.message.contains("does not exist")),
            "expected policy reference error, got {errs:?}"
        );
    }

    /// Header 转换：值里带 CR/LF 必须被拒绝（防 Header 注入）
    #[test]
    fn transform_header_injection_rejected() {
        let yaml = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
policies:
  response_transform:
    - id: t
      add_headers: [{ name: X-Bad, value: "a\r\nInjected: yes" }]
"#;
        let cfg = load_from_str(yaml).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(errs.iter().any(|e| e.message.contains("header injection")));
    }

    /// 非法 CIDR 必须被拒绝
    #[test]
    fn invalid_cidr_rejected() {
        let yaml = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
policies:
  auth:
    - id: ip
      type: ip_allowlist
      cidrs: ["10.0.0.0/40"]
"#;
        let cfg = load_from_str(yaml).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(errs.iter().any(|e| e.path.contains("cidrs")));
    }
}
