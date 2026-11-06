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
    validate_certificates(cfg, &mut errors);
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

    // TLS：必须有明确的证书来源，且文件证书必须成对出现
    let tls = &cfg.server.http.tls;
    if tls.enabled {
        let has_cert_file = tls.cert_file.is_some();
        let has_key_file = tls.key_file.is_some();
        if has_cert_file != has_key_file {
            errors.push(ConfigError {
                path: "server.http.tls".into(),
                message: "cert_file and key_file must be configured together".into(),
            });
        }

        let referenced = tls
            .certificate_id
            .as_deref()
            .and_then(|id| cfg.certificates.iter().find(|c| c.id == id));
        // 控制面引导模式（control_plane.enabled）允许本地没有任何证书：
        // 证书由控制面发布后通过配置快照下发，首个快照应用前握手会失败。
        if !has_cert_file && referenced.is_none() && !cfg.control_plane.enabled {
            errors.push(ConfigError {
                path: "server.http.tls".into(),
                message: "tls enabled but no certificate source: configure certificate_id or cert_file/key_file"
                    .into(),
            });
        }
        if referenced.is_some_and(|c| !c.enabled) {
            errors.push(ConfigError {
                path: "server.http.tls.certificate_id".into(),
                message: "referenced certificate is disabled".into(),
            });
        }
        if tls.reload_interval_secs == 0 {
            errors.push(ConfigError {
                path: "server.http.tls.reload_interval_secs".into(),
                message: "reload_interval_secs must be >= 1".into(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Certificate 校验
// ---------------------------------------------------------------------------

/// 校验证书资源：ID 唯一、PEM 结构完整、启用证书字段非空。
fn validate_certificates(cfg: &GatewayConfig, errors: &mut Vec<ConfigError>) {
    let mut seen = std::collections::HashSet::new();
    for (idx, cert) in cfg.certificates.iter().enumerate() {
        let base = format!("certificates[{idx}]");
        if cert.id.trim().is_empty() {
            errors.push(ConfigError {
                path: format!("{base}.id"),
                message: "id must not be empty".into(),
            });
        } else if !seen.insert(cert.id.clone()) {
            errors.push(ConfigError {
                path: format!("{base}.id"),
                message: format!("duplicate certificate id '{}'", cert.id),
            });
        }

        if !cert.enabled {
            continue;
        }
        if cert.cert_pem.trim().is_empty() {
            errors.push(ConfigError {
                path: format!("{base}.cert_pem"),
                message: "cert_pem must not be empty".into(),
            });
        } else if !cert.cert_pem.contains("BEGIN CERTIFICATE") {
            errors.push(ConfigError {
                path: format!("{base}.cert_pem"),
                message: "cert_pem must contain a PEM certificate".into(),
            });
        }
        if cert.key_pem.trim().is_empty() {
            errors.push(ConfigError {
                path: format!("{base}.key_pem"),
                message: "key_pem must not be empty".into(),
            });
        } else if !cert.key_pem.contains("PRIVATE KEY") {
            errors.push(ConfigError {
                path: format!("{base}.key_pem"),
                message: "key_pem must contain a PEM private key".into(),
            });
        }
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

        // ---- 健康检查配置校验 ----
        if let Some(health) = &upstream.health_check {
            let base = format!("upstreams[{idx}].health_check");
            if health.interval_secs == 0 {
                errors.push(ConfigError {
                    path: format!("{base}.interval_secs"),
                    message: "interval_secs must be >= 1".into(),
                });
            }
            if health.timeout_secs == 0 {
                errors.push(ConfigError {
                    path: format!("{base}.timeout_secs"),
                    message: "timeout_secs must be >= 1".into(),
                });
            }
            if health.unhealthy_threshold == 0 {
                errors.push(ConfigError {
                    path: format!("{base}.unhealthy_threshold"),
                    message: "unhealthy_threshold must be >= 1".into(),
                });
            }
            if health.healthy_threshold == 0 {
                errors.push(ConfigError {
                    path: format!("{base}.healthy_threshold"),
                    message: "healthy_threshold must be >= 1".into(),
                });
            }
            if health.enabled
                && matches!(health.kind, gateway_core::HealthCheckKind::Http)
                && !health.path.starts_with('/')
            {
                errors.push(ConfigError {
                    path: format!("{base}.path"),
                    message: "path must start with '/'".into(),
                });
            }
            if let Some(expr) = &health.expected_status {
                if let Err(reason) = gateway_core::parse_expected_status(expr) {
                    errors.push(ConfigError {
                        path: format!("{base}.expected_status"),
                        message: format!("invalid expected_status: {reason}"),
                    });
                }
            }
            if health.passive.failure_threshold == 0 {
                errors.push(ConfigError {
                    path: format!("{base}.passive.failure_threshold"),
                    message: "failure_threshold must be >= 1".into(),
                });
            }
            if health.passive.recovery_threshold == 0 {
                errors.push(ConfigError {
                    path: format!("{base}.passive.recovery_threshold"),
                    message: "recovery_threshold must be >= 1".into(),
                });
            }
        }

        // ---- Phase 6：动态服务发现配置校验 ----
        if let Some(discovery) = &upstream.discovery {
            let base = format!("upstreams[{idx}].discovery");
            match discovery.provider {
                gateway_core::DiscoveryProviderKind::Static => {
                    errors.push(ConfigError {
                        path: format!("{base}.provider"),
                        message:
                            "discovery.provider must be 'dns' or 'kubernetes' when discovery is set"
                                .into(),
                    });
                },
                gateway_core::DiscoveryProviderKind::Dns => {
                    if discovery.domain.as_deref().map(|v| v.trim().is_empty()).unwrap_or(true) {
                        errors.push(ConfigError {
                            path: format!("{base}.domain"),
                            message: "discovery.domain is required for dns provider".into(),
                        });
                    }
                    if let Some(resolver) = discovery.dns_resolver.as_deref() {
                        if resolver.parse::<std::net::SocketAddr>().is_err() {
                            errors.push(ConfigError {
                                path: format!("{base}.dns_resolver"),
                                message: format!(
                                    "invalid dns_resolver '{resolver}', expected host:port"
                                ),
                            });
                        }
                    }
                },
                gateway_core::DiscoveryProviderKind::Kubernetes => {
                    if discovery.namespace.as_deref().map(|v| v.trim().is_empty()).unwrap_or(true) {
                        errors.push(ConfigError {
                            path: format!("{base}.namespace"),
                            message: "discovery.namespace is required for kubernetes provider"
                                .into(),
                        });
                    }
                    if discovery.service.as_deref().map(|v| v.trim().is_empty()).unwrap_or(true) {
                        errors.push(ConfigError {
                            path: format!("{base}.service"),
                            message: "discovery.service is required for kubernetes provider".into(),
                        });
                    }
                },
            }
            if discovery.refresh_interval_secs == 0 {
                errors.push(ConfigError {
                    path: format!("{base}.refresh_interval_secs"),
                    message: "refresh_interval_secs must be >= 1".into(),
                });
            }
            // 配置了动态发现却没有任何端点时，SDK 无法推导默认端口（DNS A 记录模式）
            if discovery.provider == gateway_core::DiscoveryProviderKind::Dns
                && upstream.endpoints.is_empty()
                && discovery.dns_record == gateway_core::DnsRecordKind::A
            {
                errors.push(ConfigError {
                    path: format!("{base}.dns_record"),
                    message: "dns A-record discovery requires at least one static endpoint to derive default port"
                        .into(),
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
    // Service ID 集合：用于灰度/镜像目标的引用完整性校验
    let service_ids: HashSet<&str> = cfg.services.iter().map(|s| s.id.as_str()).collect();

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

        // ---- Phase 6：灰度 / 蓝绿 / 加权路由校验 ----
        if let Some(split) = &route.traffic_split {
            if split.targets.is_empty() {
                errors.push(ConfigError {
                    path: format!("{base}.traffic_split.targets"),
                    message: "traffic_split.targets must not be empty".into(),
                });
            }
            let mut total_weight: u64 = 0;
            for (t_idx, target) in split.targets.iter().enumerate() {
                total_weight += u64::from(target.weight);
                if !service_ids.contains(target.service_id.as_str()) {
                    errors.push(ConfigError {
                        path: format!("{base}.traffic_split.targets[{t_idx}].service_id"),
                        message: format!(
                            "traffic_split target service '{}' does not exist",
                            target.service_id
                        ),
                    });
                }
                // 注意：targets 允许包含 route.service_id —— 灰度发布常见
                // 形态就是「稳定版 + 金丝雀」按权重分流。
            }
            if total_weight == 0 {
                errors.push(ConfigError {
                    path: format!("{base}.traffic_split.targets"),
                    message: "traffic_split total weight must be greater than 0".into(),
                });
            }
        }

        // ---- Phase 6：流量镜像校验 ----
        if let Some(mirror) = &route.mirror {
            if mirror.percentage > 100 {
                errors.push(ConfigError {
                    path: format!("{base}.mirror.percentage"),
                    message: "mirror.percentage must be in 0..=100".into(),
                });
            }
            if !service_ids.contains(mirror.service_id.as_str()) {
                errors.push(ConfigError {
                    path: format!("{base}.mirror.service_id"),
                    message: format!("mirror service '{}' does not exist", mirror.service_id),
                });
            }
            // 镜像到自身会造成请求回路（影子请求再次被镜像）
            if mirror.service_id == route.service_id {
                errors.push(ConfigError {
                    path: format!("{base}.mirror.service_id"),
                    message: "mirror.service_id must differ from route.service_id".into(),
                });
            }
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

            // ---- API Key（支持生命周期元数据）----
            AuthPolicySpec::ApiKey {
                keys,
                header_name,
                query_param,
                required_scopes,
            } => {
                if keys.is_empty() {
                    errors.push(ConfigError {
                        path: format!("{base}.keys"),
                        message: "keys must not be empty".into(),
                    });
                }

                let mut seen_ids: HashSet<&str> = HashSet::new();
                let mut seen_hashes: HashSet<String> = HashSet::new();
                let mut seen_plaintext: HashSet<&str> = HashSet::new();

                for (key_idx, key) in keys.iter().enumerate() {
                    let entry = format!("{base}.keys[{key_idx}]");

                    // 明文与摘要必须提供且仅提供其一
                    match (key.key.is_empty(), key.key_hash.as_deref()) {
                        (false, _) => {
                            if !seen_plaintext.insert(key.key.as_str()) {
                                errors.push(ConfigError {
                                    path: format!("{entry}.key"),
                                    message: "duplicate api key value".into(),
                                });
                            }
                        },
                        (true, Some(hash)) => {
                            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                                errors.push(ConfigError {
                                    path: format!("{entry}.key_hash"),
                                    message: "key_hash must be 64 hex characters (SHA-256 digest)"
                                        .into(),
                                });
                            }
                            if !seen_hashes.insert(hash.to_ascii_lowercase()) {
                                errors.push(ConfigError {
                                    path: format!("{entry}.key_hash"),
                                    message: "duplicate api key hash".into(),
                                });
                            }
                        },
                        (true, None) => errors.push(ConfigError {
                            path: format!("{entry}.key"),
                            message:
                                "either 'key' (plaintext) or 'key_hash' (sha256) must be provided"
                                    .into(),
                        }),
                    }

                    // ID 是吊销 / 轮换 / 用量统计的索引，必须唯一
                    if let Some(id) = key.id.as_deref() {
                        if id.is_empty() {
                            errors.push(ConfigError {
                                path: format!("{entry}.id"),
                                message: "id must not be empty".into(),
                            });
                        } else if !seen_ids.insert(id) {
                            errors.push(ConfigError {
                                path: format!("{entry}.id"),
                                message: format!("duplicate api key id '{id}'"),
                            });
                        }
                    }

                    // 过期时间为 0 等价于"立即过期"，几乎总是配置错误
                    if key.expires_at == Some(0) {
                        errors.push(ConfigError {
                            path: format!("{entry}.expires_at"),
                            message: "expires_at must be a positive unix timestamp".into(),
                        });
                    }

                    for (scope_idx, scope) in key.scopes.iter().enumerate() {
                        if scope.is_empty() {
                            errors.push(ConfigError {
                                path: format!("{entry}.scopes[{scope_idx}]"),
                                message: "scope must not be empty".into(),
                            });
                        }
                    }

                    // 注意：`revoked = true` 的条目会被认证层持续拒绝 401，
                    // 这是合法配置（保留记录用于审计），因此不报错。
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
                for (scope_idx, scope) in required_scopes.iter().enumerate() {
                    if scope.is_empty() {
                        errors.push(ConfigError {
                            path: format!("{base}.required_scopes[{scope_idx}]"),
                            message: "required scope must not be empty".into(),
                        });
                    }
                }
            },

            // ---- JWT（HMAC 静态密钥 / JWKS 非对称公钥）----
            AuthPolicySpec::Jwt {
                secret,
                algorithms,
                leeway_secs,
                header_name,
                query_param,
                validate_exp,
                jwks,
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

                let needs_hmac = algorithms.iter().any(|alg| alg.is_hmac());
                let needs_jwks = algorithms.iter().any(|alg| !alg.is_hmac());

                // HMAC 必须提供 non-empty secret（且至少 32 字节）
                match secret {
                    None => {
                        if needs_hmac {
                            errors.push(ConfigError {
                                path: format!("{base}.secret"),
                                message: "secret is required for HS256/HS384/HS512".into(),
                            });
                        }
                    },
                    Some(s) if s.is_empty() => errors.push(ConfigError {
                        path: format!("{base}.secret"),
                        message: "secret must not be empty".into(),
                    }),
                    // HMAC-SHA256 的安全强度下限：短于 32 字节的密钥容易离线暴力破解
                    Some(s) if needs_hmac && s.len() < 32 => errors.push(ConfigError {
                        path: format!("{base}.secret"),
                        message: "secret should be at least 32 bytes for HS256 security".into(),
                    }),
                    Some(_) => {},
                }

                // 非对称算法必须提供合法 JWKS 文档
                match jwks {
                    None => {
                        if needs_jwks {
                            errors.push(ConfigError {
                                path: format!("{base}.jwks"),
                                message: "jwks is required for RS*/ES* algorithms".into(),
                            });
                        }
                    },
                    Some(document) => match serde_json::from_str::<serde_json::Value>(document) {
                        Ok(value) => match value.get("keys").and_then(|keys| keys.as_array()) {
                            Some(keys) if keys.is_empty() => errors.push(ConfigError {
                                path: format!("{base}.jwks"),
                                message: "jwks.keys must not be empty".into(),
                            }),
                            Some(_) => {},
                            None => errors.push(ConfigError {
                                path: format!("{base}.jwks"),
                                message: "jwks must be a JSON object with a 'keys' array".into(),
                            }),
                        },
                        Err(e) => errors.push(ConfigError {
                            path: format!("{base}.jwks"),
                            message: format!("invalid JWKS JSON: {e}"),
                        }),
                    },
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
    let waf_ids: HashSet<&str> = cfg.policies.waf.iter().map(|p| p.id.as_str()).collect();
    let quota_ids: HashSet<&str> = cfg.policies.quota.iter().map(|p| p.id.as_str()).collect();

    // 逐条 Route 检查策略引用（None 表示未引用，直接通过）
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
        check_policy_ref(
            route.waf_policy_id.as_ref(),
            &waf_ids,
            format!("routes[{idx}].waf_policy_id"),
            "policies.waf",
            errors,
        );
        check_policy_ref(
            route.quota_policy_id.as_ref(),
            &quota_ids,
            format!("routes[{idx}].quota_policy_id"),
            "policies.quota",
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

    /// JWT：算法白名单为空 / 白名单含 HS* 但缺少 secret 都必须报错
    #[test]
    fn jwt_policy_requires_whitelist_and_secret() {
        // 1) 算法白名单为空
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

        // 2) HS* 白名单缺少 secret
        let yaml = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
policies:
  auth:
    - id: jwt-no-secret
      type: jwt
      algorithms: [HS256]
"#;
        let cfg = load_from_str(yaml).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(
            errs.iter().any(|e| e.path.contains("secret")),
            "expected secret error, got {errs:?}"
        );
    }

    /// JWT：RS256 白名单必须配置合法 JWKS，且无需 secret
    #[test]
    fn jwt_asymmetric_requires_jwks() {
        let base = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
policies:
  auth:
    - id: jwt-rs
      type: jwt
      algorithms: [RS256]
"#;
        let cfg = load_from_str(base).unwrap();
        let errs = validate(&cfg).expect_err("should fail without jwks");
        assert!(
            errs.iter().any(|e| e.path.contains("jwks")),
            "expected jwks error, got {errs:?}"
        );

        let with_jwks = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
policies:
  auth:
    - id: jwt-rs
      type: jwt
      algorithms: [RS256]
      jwks: '{"keys":[{"kty":"RSA","kid":"k1","n":"abc","e":"AQAB"}]}'
"#;
        let cfg = load_from_str(with_jwks).unwrap();
        assert!(validate(&cfg).is_ok(), "errors: {:?}", validate(&cfg).err());
    }

    /// API Key：key_hash 必须是 64 位十六进制；key 与 key_hash 必须二选一
    #[test]
    fn api_key_lifecycle_fields_are_validated() {
        let bad_hash = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
policies:
  auth:
    - id: keys
      type: api_key
      keys:
        - key_hash: "zz"
"#;
        let cfg = load_from_str(bad_hash).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(
            errs.iter().any(|e| e.path.contains("key_hash")),
            "expected key_hash error, got {errs:?}"
        );

        let missing_source = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
policies:
  auth:
    - id: keys
      type: api_key
      keys:
        - label: caller-a
"#;
        let cfg = load_from_str(missing_source).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(
            errs.iter().any(|e| e.path.contains("key")),
            "expected key source error, got {errs:?}"
        );

        let valid = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
policies:
  auth:
    - id: keys
      type: api_key
      required_scopes: [orders:read]
      keys:
        - id: k1
          key_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
          consumer_id: consumer-a
          scopes: [orders:read]
          expires_at: 4102444800
"#;
        let cfg = load_from_str(valid).unwrap();
        assert!(validate(&cfg).is_ok(), "errors: {:?}", validate(&cfg).err());
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

    /// TLS 启用但未配置任何证书来源必须被拒绝
    #[test]
    fn tls_requires_certificate_source() {
        let yaml = r#"
gateway: { id: g }
server:
  http:
    port: 8080
    tls: { enabled: true }
"#;
        let cfg = load_from_str(yaml).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(errs
            .iter()
            .any(|e| e.path == "server.http.tls" && e.message.contains("no certificate source")));
    }

    /// 文件证书必须 cert_file/key_file 成对出现
    #[test]
    fn tls_file_certificate_requires_both_files() {
        let yaml = r#"
gateway: { id: g }
server:
  http:
    port: 8080
    tls: { enabled: true, cert_file: /tmp/server.crt }
"#;
        let cfg = load_from_str(yaml).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(errs.iter().any(|e| e.message.contains("must be configured together")));
    }

    /// 文件证书成对配置即可通过（文件存在性在运行时检查）
    #[test]
    fn tls_file_certificate_pair_is_valid() {
        let yaml = r#"
gateway: { id: g }
server:
  http:
    port: 8080
    tls:
      enabled: true
      cert_file: /tmp/server.crt
      key_file: /tmp/server.key
      domains: ["api.example.com"]
"#;
        let cfg = load_from_str(yaml).unwrap();
        assert!(validate(&cfg).is_ok());
    }

    /// 证书资源 PEM 结构非法必须被拒绝
    #[test]
    fn invalid_certificate_pem_rejected() {
        let yaml = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
certificates:
  - id: bad
    enabled: true
    cert_pem: "not a certificate"
    key_pem: "not a key"
"#;
        let cfg = load_from_str(yaml).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(errs
            .iter()
            .any(|e| e.path.contains("cert_pem") && e.message.contains("PEM certificate")));
        assert!(errs
            .iter()
            .any(|e| e.path.contains("key_pem") && e.message.contains("PEM private key")));
    }

    /// 未启用的证书允许保存草稿（不做 PEM 校验）
    #[test]
    fn disabled_certificate_allows_empty_material() {
        let yaml = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
certificates:
  - id: draft
    enabled: false
    cert_pem: ""
    key_pem: ""
"#;
        let cfg = load_from_str(yaml).unwrap();
        assert!(validate(&cfg).is_ok());
    }

    /// 控制面引导模式：本地没有证书也允许启动（证书由控制面下发）
    #[test]
    fn control_plane_mode_allows_tls_without_local_certificate() {
        let yaml = r#"
gateway: { id: g }
server:
  http:
    port: 8443
    tls: { enabled: true, certificate_id: "api-cert" }
control_plane:
  enabled: true
  endpoint: "http://localhost:8092"
"#;
        let cfg = load_from_str(yaml).unwrap();
        assert!(validate(&cfg).is_ok(), "errors: {:?}", validate(&cfg).err());
    }

    /// 控制面引导模式下文件证书仍必须成对配置
    #[test]
    fn control_plane_mode_still_requires_paired_file_certificate() {
        let yaml = r#"
gateway: { id: g }
server:
  http:
    port: 8443
    tls: { enabled: true, cert_file: /tmp/server.crt }
control_plane:
  enabled: true
  endpoint: "http://localhost:8092"
"#;
        let cfg = load_from_str(yaml).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        assert!(errs.iter().any(|e| e.message.contains("must be configured together")));
    }

    /// 合法健康检查配置通过校验
    #[test]
    fn valid_health_check_passes() {
        let yaml = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
upstreams:
  - id: u1
    endpoints:
      - { host: 127.0.0.1, port: 9000 }
    health_check:
      enabled: true
      kind: http
      path: /healthz
      interval_secs: 5
      timeout_secs: 2
      unhealthy_threshold: 3
      healthy_threshold: 2
      expected_status: "200-299"
      passive: { enabled: true, failure_threshold: 5, recovery_threshold: 3 }
"#;
        let cfg = load_from_str(yaml).unwrap();
        assert!(validate(&cfg).is_ok(), "errors: {:?}", validate(&cfg).err());
    }

    /// 范围表达式合法、非法表达式被拒绝
    #[test]
    fn expected_status_range_expression_is_validated() {
        let valid = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
upstreams:
  - id: u1
    endpoints: [{ host: 127.0.0.1, port: 9000 }]
    health_check: { expected_status: "200-399" }
"#;
        let cfg = load_from_str(valid).unwrap();
        assert!(validate(&cfg).is_ok());

        for bad in ["\"600-700\"", "\"99\"", "\"abc\"", "\"300-200\""] {
            let yaml = format!(
                r#"
gateway: {{ id: g }}
server: {{ http: {{ port: 8080 }} }}
upstreams:
  - id: u1
    endpoints: [{{ host: 127.0.0.1, port: 9000 }}]
    health_check: {{ expected_status: {bad} }}
"#
            );
            let cfg = load_from_str(&yaml).unwrap();
            let errs = validate(&cfg).expect_err("should fail");
            assert!(
                errs.iter().any(|e| e.path.ends_with("expected_status")),
                "expression {bad} should be rejected, errors: {errs:?}"
            );
        }
    }

    /// 非法健康检查配置被拒绝
    #[test]
    fn invalid_health_check_is_rejected() {
        let yaml = r#"
gateway: { id: g }
server: { http: { port: 8080 } }
upstreams:
  - id: u1
    endpoints:
      - { host: 127.0.0.1, port: 9000 }
    health_check:
      interval_secs: 0
      timeout_secs: 0
      unhealthy_threshold: 0
      healthy_threshold: 0
      path: healthz
      expected_status: "999"
      passive: { failure_threshold: 0, recovery_threshold: 0 }
"#;
        let cfg = load_from_str(yaml).unwrap();
        let errs = validate(&cfg).expect_err("should fail");
        let paths: Vec<&str> = errs.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.iter().any(|p| p.ends_with("interval_secs")));
        assert!(paths.iter().any(|p| p.ends_with("timeout_secs")));
        assert!(paths.iter().any(|p| p.ends_with("unhealthy_threshold")));
        assert!(paths.iter().any(|p| p.ends_with("healthy_threshold")));
        assert!(paths.iter().any(|p| p.ends_with("path")));
        assert!(paths.iter().any(|p| p.ends_with("expected_status")));
        assert!(paths.iter().any(|p| p.ends_with("passive.failure_threshold")));
        assert!(paths.iter().any(|p| p.ends_with("passive.recovery_threshold")));
    }
}
