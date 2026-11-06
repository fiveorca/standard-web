//! 配置校验。
//!
//! 校验分为错误（阻止启动）与告警（允许启动但记录日志）两类。

use std::collections::HashSet;
use std::fmt;

use ipnet::IpNet;
use url::Url;

use crate::config::model::*;
use crate::core::filter::FilterRegistry;
use crate::core::predicate::Predicate;

/// 校验级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// 单条校验结果。
#[derive(Debug, Clone)]
pub struct Issue {
    pub severity: Severity,
    pub field: String,
    pub message: String,
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let level = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(f, "[{level}] {}: {}", self.field, self.message)
    }
}

/// 校验结果集合。
#[derive(Debug, Default)]
pub struct ValidationReport {
    pub issues: Vec<Issue>,
}

impl ValidationReport {
    pub fn error(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.issues.push(Issue {
            severity: Severity::Error,
            field: field.into(),
            message: message.into(),
        });
    }

    pub fn warn(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.issues.push(Issue {
            severity: Severity::Warning,
            field: field.into(),
            message: message.into(),
        });
    }

    pub fn has_errors(&self) -> bool {
        self.issues.iter().any(|i| i.severity == Severity::Error)
    }

    pub fn errors(&self) -> impl Iterator<Item = &Issue> {
        self.issues.iter().filter(|i| i.severity == Severity::Error)
    }

    pub fn warnings(&self) -> impl Iterator<Item = &Issue> {
        self.issues
            .iter()
            .filter(|i| i.severity == Severity::Warning)
    }
}

/// 校验完整配置。
pub fn validate(config: &GatewayConfig, registry: &FilterRegistry) -> ValidationReport {
    let mut report = ValidationReport::default();
    let gateway = &config.gateway;

    // server
    if gateway.server.port == 0 {
        report.error("gateway.server.port", "port must not be 0");
    }
    if gateway.server.max_connections == 0 {
        report.warn(
            "gateway.server.max_connections",
            "0 means unlimited connections, which may exhaust resources",
        );
    }
    if gateway.server.tls.enabled {
        if gateway.server.tls.cert_path.is_none() {
            report.error(
                "gateway.server.tls.cert_path",
                "TLS is enabled but cert_path is not configured",
            );
        }
        if gateway.server.tls.key_path.is_none() {
            report.error(
                "gateway.server.tls.key_path",
                "TLS is enabled but key_path is not configured",
            );
        }
        if !matches!(gateway.server.tls.min_version.as_str(), "1.2" | "1.3") {
            report.error(
                "gateway.server.tls.min_version",
                "min_version must be `1.2` or `1.3`",
            );
        }
    }

    validate_admin(gateway, &mut report);
    validate_auth(gateway, &mut report);
    validate_rate_limit(gateway, &mut report);
    validate_cors(gateway.cors.as_ref(), "gateway.cors", &mut report);
    validate_ip_filter(&gateway.ip_filter, "gateway.ip_filter", &mut report);
    validate_trusted_proxies(&gateway.server.trusted_proxies, &mut report);

    if !gateway.upstream_tls.verify {
        report.warn(
            "gateway.upstream_tls.verify",
            "upstream TLS verification is disabled; this is unsafe outside development",
        );
    }

    for (name, service) in &gateway.services {
        validate_service(name, service, &mut report);
    }

    if config.routes.is_empty() {
        report.warn(
            "routes",
            "no routes configured; the gateway will return 404 for all requests",
        );
    }

    let mut seen_ids = HashSet::new();
    for (idx, route) in config.routes.iter().enumerate() {
        let field = format!("routes[{idx}]");
        if route.id.trim().is_empty() {
            report.error(format!("{field}.id"), "route id must not be empty");
        }
        if !seen_ids.insert(route.id.clone()) {
            report.error(
                format!("{field}.id"),
                format!("duplicate route id `{}`", route.id),
            );
        }
        validate_uri(&route.uri, &format!("{field}.uri"), &mut report);
        if route.uri.starts_with("lb://") {
            let service = route.uri.trim_start_matches("lb://");
            if service.is_empty() {
                report.error(format!("{field}.uri"), "lb:// requires a service name");
            }
        }
        if route.predicates.is_empty() {
            report.error(
                format!("{field}.predicates"),
                "route must declare at least one predicate",
            );
        }
        for (pidx, predicate) in route.predicates.iter().enumerate() {
            if let Err(err) = Predicate::parse(predicate) {
                report.error(format!("{field}.predicates[{pidx}]"), err);
            }
        }
        for (fidx, filter) in route.filters.iter().enumerate() {
            if let Err(err) = registry.create(filter) {
                report.error(format!("{field}.filters[{fidx}]"), err);
            }
        }
        validate_cors(route.cors.as_ref(), &format!("{field}.cors"), &mut report);
        if let Some(ip) = &route.ip_filter {
            validate_ip_filter(ip, &format!("{field}.ip_filter"), &mut report);
        }
        if let Some(rate) = &route.rate_limit {
            if rate.enabled
                && rate.key_type == RateLimitKeyType::Custom
                && rate.key_template.is_none()
            {
                report.error(
                    format!("{field}.rate_limit.key_template"),
                    "custom key type requires key_template",
                );
            }
            if rate.enabled && rate.quota.rate_per_second() <= 0.0 {
                report.error(
                    format!("{field}.rate_limit.quota"),
                    "rate limit quota must be greater than 0",
                );
            }
        }
        if let Some(cb) = &route.circuit_breaker {
            if cb.enabled {
                if cb.failure_rate_threshold <= 0.0 || cb.failure_rate_threshold > 100.0 {
                    report.error(
                        format!("{field}.circuit_breaker.failure_rate_threshold"),
                        "failure_rate_threshold must be in (0, 100]",
                    );
                }
                if cb.minimum_requests == 0 {
                    report.error(
                        format!("{field}.circuit_breaker.minimum_requests"),
                        "minimum_requests must be greater than 0",
                    );
                }
            }
        }
        if let Some(retry) = &route.retry {
            if retry.enabled && retry.max_attempts == 0 {
                report.error(
                    format!("{field}.retry.max_attempts"),
                    "max_attempts must be greater than 0 when retry is enabled",
                );
            }
            if retry.enabled && retry.backoff_multiplier < 1.0 {
                report.error(
                    format!("{field}.retry.backoff_multiplier"),
                    "backoff_multiplier must be >= 1.0",
                );
            }
        }
        if let Some(auth) = &route.authentication {
            if auth.mode == AuthMode::Authenticated && gateway.authentication.jwt.is_none() {
                report.error(
                    format!("{field}.authentication"),
                    "route requires authentication but gateway.authentication.jwt is not configured",
                );
            }
        }
        if let Some(authz) = &route.authorization {
            if authz.provider == "external" {
                match &authz.external {
                    None => report.error(
                        format!("{field}.authorization.external"),
                        "external authorization requires an external config",
                    ),
                    Some(ext) if ext.url.is_empty() => report.error(
                        format!("{field}.authorization.external.url"),
                        "external authorization url must not be empty",
                    ),
                    Some(_) => {}
                }
            }
        }
    }

    report
}

fn validate_admin(gateway: &GatewaySection, report: &mut ValidationReport) {
    if !gateway.admin.enabled {
        return;
    }
    if gateway.admin.port == gateway.server.port && gateway.admin.port == 0 {
        report.error("gateway.admin.port", "admin port must not be 0");
    }
    match gateway.admin.auth.mode.as_str() {
        "api_key" => {
            if gateway.admin.auth.api_keys.is_empty() {
                report.warn(
                    "gateway.admin.auth.api_keys",
                    "no admin API key configured; all admin requests will be rejected",
                );
            }
        }
        "jwt" => {
            if gateway.admin.auth.jwt.is_none() {
                report.error(
                    "gateway.admin.auth.jwt",
                    "admin auth mode is jwt but no jwt config is provided",
                );
            }
        }
        "none" => report.warn(
            "gateway.admin.auth.mode",
            "admin authentication is disabled; only do this behind a trusted network",
        ),
        other => report.error(
            "gateway.admin.auth.mode",
            format!("unsupported admin auth mode `{other}`"),
        ),
    }
    for (idx, ip) in gateway.admin.allowed_ips.iter().enumerate() {
        if ip.parse::<IpNet>().is_err() {
            report.error(
                format!("gateway.admin.allowed_ips[{idx}]"),
                format!("invalid CIDR `{ip}`"),
            );
        }
    }
}

fn validate_auth(gateway: &GatewaySection, report: &mut ValidationReport) {
    if let Some(jwt) = &gateway.authentication.jwt {
        let mut has_hmac = false;
        let mut has_asymmetric = false;
        for alg in &jwt.algorithms {
            match alg.to_ascii_uppercase().as_str() {
                "HS256" | "HS384" | "HS512" => has_hmac = true,
                "RS256" | "RS384" | "RS512" | "ES256" | "ES384" => has_asymmetric = true,
                "NONE" | "NONE256" => report.error(
                    "gateway.authentication.jwt.algorithms",
                    "algorithm `none` is not allowed",
                ),
                other => report.error(
                    "gateway.authentication.jwt.algorithms",
                    format!("unsupported algorithm `{other}`"),
                ),
            }
        }
        if has_hmac {
            let has_secret = jwt.secret.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
                || jwt
                    .secret_env
                    .as_ref()
                    .map(|s| !s.is_empty())
                    .unwrap_or(false);
            if !has_secret {
                report.error(
                    "gateway.authentication.jwt.secret",
                    "HMAC algorithms require `secret` or `secret_env`",
                );
            }
            if let Some(secret) = &jwt.secret {
                if secret.len() < 32 {
                    report.warn(
                        "gateway.authentication.jwt.secret",
                        "HMAC secret shorter than 32 bytes is considered weak",
                    );
                }
            }
        }
        if has_asymmetric && jwt.jwks_uri.is_none() {
            report.error(
                "gateway.authentication.jwt.jwks_uri",
                "asymmetric algorithms require `jwks_uri`",
            );
        }
        if let Some(uri) = &jwt.jwks_uri {
            if Url::parse(uri).is_err() {
                report.error(
                    "gateway.authentication.jwt.jwks_uri",
                    format!("invalid URL `{uri}`"),
                );
            }
        }
    }
    for (idx, key) in gateway.authentication.api_keys.iter().enumerate() {
        if key.key.is_none() && key.key_hash.is_none() {
            report.error(
                format!("gateway.authentication.api_keys[{idx}]"),
                "api key requires either `key` or `key_hash`",
            );
        }
        if let Some(hash) = &key.key_hash {
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                report.error(
                    format!("gateway.authentication.api_keys[{idx}].key_hash"),
                    "key_hash must be a 64 character hex encoded SHA-256 digest",
                );
            }
        }
    }
}

fn validate_rate_limit(gateway: &GatewaySection, report: &mut ValidationReport) {
    let rl = &gateway.rate_limit;
    if !rl.enabled {
        return;
    }
    if rl.mode == RateLimitMode::Redis && gateway.redis.url.is_empty() {
        report.error(
            "gateway.redis.url",
            "redis rate limit mode requires gateway.redis.url",
        );
    }
    if rl.max_keys == 0 {
        report.error(
            "gateway.rate_limit.max_keys",
            "max_keys must be greater than 0",
        );
    }
    if rl.quota.rate_per_second() <= 0.0 {
        report.error(
            "gateway.rate_limit.quota",
            "rate limit quota must be greater than 0",
        );
    }
}

fn validate_cors(cors: Option<&CorsConfig>, field: &str, report: &mut ValidationReport) {
    let Some(cors) = cors else { return };
    if cors.allow_credentials && cors.allowed_origins.iter().any(|o| o == "*") {
        report.error(
            format!("{field}.allowed_origins"),
            "wildcard origin cannot be combined with allow_credentials=true",
        );
    }
    for origin in &cors.allowed_origins {
        if origin != "*" && Url::parse(origin).is_err() {
            report.warn(
                format!("{field}.allowed_origins"),
                format!("`{origin}` is not a valid absolute origin"),
            );
        }
    }
}

fn validate_ip_filter(filter: &IpFilterConfig, field: &str, report: &mut ValidationReport) {
    for (idx, cidr) in filter.allow.iter().enumerate() {
        if cidr.parse::<IpNet>().is_err() {
            report.error(
                format!("{field}.allow[{idx}]"),
                format!("invalid CIDR `{cidr}`"),
            );
        }
    }
    for (idx, cidr) in filter.deny.iter().enumerate() {
        if cidr.parse::<IpNet>().is_err() {
            report.error(
                format!("{field}.deny[{idx}]"),
                format!("invalid CIDR `{cidr}`"),
            );
        }
    }
}

fn validate_trusted_proxies(proxies: &[String], report: &mut ValidationReport) {
    for (idx, cidr) in proxies.iter().enumerate() {
        if cidr.parse::<IpNet>().is_err() {
            report.error(
                format!("gateway.server.trusted_proxies[{idx}]"),
                format!("invalid CIDR `{cidr}`"),
            );
        }
    }
}

fn validate_service(name: &str, service: &ServiceConfig, report: &mut ValidationReport) {
    match service.discovery.as_str() {
        "static" => {
            if service.instances.is_empty() {
                report.error(
                    format!("gateway.services.{name}.instances"),
                    "static discovery requires at least one instance",
                );
            }
            for (idx, instance) in service.instances.iter().enumerate() {
                validate_uri(
                    &instance.uri,
                    &format!("gateway.services.{name}.instances[{idx}].uri"),
                    report,
                );
                if instance.weight == 0 {
                    report.warn(
                        format!("gateway.services.{name}.instances[{idx}].weight"),
                        "weight 0 means the instance will never be selected",
                    );
                }
            }
        }
        "consul" => {
            if service.consul_service.is_none() && name.is_empty() {
                report.error(
                    format!("gateway.services.{name}.consul_service"),
                    "consul discovery requires a service name",
                );
            }
        }
        other => report.error(
            format!("gateway.services.{name}.discovery"),
            format!("unsupported discovery `{other}`"),
        ),
    }
}

fn validate_uri(uri: &str, field: &str, report: &mut ValidationReport) {
    if uri.starts_with("lb://") {
        if uri.trim_start_matches("lb://").trim().is_empty() {
            report.error(field, "lb:// requires a service name");
        }
        return;
    }
    match Url::parse(uri) {
        Ok(url) => {
            if !matches!(url.scheme(), "http" | "https") {
                report.error(field, format!("unsupported scheme `{}`", url.scheme()));
            }
            if url.host_str().is_none() {
                report.error(field, "uri must contain a host");
            }
        }
        Err(err) => report.error(field, format!("invalid uri `{uri}`: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> GatewayConfig {
        serde_yaml::from_str(
            r#"
gateway:
  server:
    port: 8080
routes:
  - id: demo
    uri: http://127.0.0.1:8081
    predicates:
      - Path=/demo/**
    filters:
      - StripPrefix=1
"#,
        )
        .unwrap()
    }

    #[test]
    fn valid_config_passes() {
        let config = base_config();
        let report = validate(&config, &FilterRegistry::builtin());
        assert!(!report.has_errors(), "{:?}", report.issues);
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let mut config = base_config();
        config.routes.push(config.routes[0].clone());
        let report = validate(&config, &FilterRegistry::builtin());
        assert!(report.has_errors());
    }

    #[test]
    fn unknown_filter_is_rejected() {
        let mut config = base_config();
        config.routes[0]
            .filters
            .push(FilterSpec::Short("NotAFilter=1".into()));
        let report = validate(&config, &FilterRegistry::builtin());
        assert!(report.has_errors());
    }

    #[test]
    fn cors_wildcard_with_credentials_is_rejected() {
        let mut config = base_config();
        config.gateway.cors = Some(CorsConfig {
            allow_credentials: true,
            ..Default::default()
        });
        let report = validate(&config, &FilterRegistry::builtin());
        assert!(report.has_errors());
    }
}
