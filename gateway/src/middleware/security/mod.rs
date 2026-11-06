//! 安全相关：Host 校验、安全响应头、上游地址（SSRF）校验。

use std::net::IpAddr;
use std::time::Duration;

use http::header::{HeaderMap, HeaderName, HeaderValue, HOST};
use moka::future::Cache;

use crate::config::model::HostValidationConfig;
use crate::error::{GatewayError, Result};
use crate::utils::http::host_without_port;

/// 校验 Host 头。
pub fn validate_host(headers: &HeaderMap, config: &HostValidationConfig) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }
    let host = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(host_without_port)
        .unwrap_or_default();
    if host.is_empty() {
        return Err(GatewayError::BadRequest("missing Host header".to_string()));
    }
    let allowed = config.allowed_hosts.iter().any(|pattern| {
        if pattern == "*" {
            return true;
        }
        if let Some(suffix) = pattern.strip_prefix("*.") {
            return host.eq_ignore_ascii_case(suffix)
                || host
                    .to_ascii_lowercase()
                    .ends_with(&format!(".{}", suffix.to_ascii_lowercase()));
        }
        host.eq_ignore_ascii_case(pattern)
    });
    if allowed {
        Ok(())
    } else {
        Err(GatewayError::Forbidden(format!(
            "host `{host}` is not allowed"
        )))
    }
}

/// 写入安全响应头。
pub fn apply_security_headers(
    headers: &mut HeaderMap,
    extra: &std::collections::HashMap<String, String>,
) {
    let defaults: [(&str, &str); 5] = [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        (
            "permissions-policy",
            "geolocation=(), microphone=(), camera=()",
        ),
        ("cross-origin-resource-policy", "same-site"),
    ];
    for (name, value) in defaults {
        if !headers.contains_key(name) {
            let name = HeaderName::from_static(name);
            headers.insert(name, HeaderValue::from_static(value));
        }
    }
    for (name, value) in extra {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(name, value);
        }
    }
}

/// 判断 IP 是否属于私网、回环、链路本地、保留地址等不应被代理的目标。
pub fn is_private_or_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 198 && (18..=19).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_private_or_reserved(IpAddr::V4(mapped));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// 上游地址守卫：防止 SSRF。
pub struct UpstreamGuard {
    enabled: bool,
    cache: Cache<String, bool>,
}

impl UpstreamGuard {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            cache: Cache::builder()
                .time_to_live(Duration::from_secs(60))
                .max_capacity(10_000)
                .build(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// 校验目标主机是否允许被代理。
    pub async fn check(&self, host: &str, port: u16) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            return if is_private_or_reserved(ip) {
                Err(GatewayError::Forbidden(format!(
                    "upstream address `{host}` is private or reserved"
                )))
            } else {
                Ok(())
            };
        }

        if let Some(allowed) = self.cache.get(host).await {
            return if allowed {
                Ok(())
            } else {
                Err(GatewayError::Forbidden(format!(
                    "upstream host `{host}` resolves to a private address"
                )))
            };
        }

        let lookup = tokio::net::lookup_host((host, port)).await;
        let allowed = match lookup {
            Ok(addrs) => {
                let mut any = false;
                let mut all_public = true;
                for addr in addrs {
                    any = true;
                    if is_private_or_reserved(addr.ip()) {
                        all_public = false;
                        break;
                    }
                }
                any && all_public
            }
            Err(_) => false,
        };
        self.cache.insert(host.to_string(), allowed).await;
        if allowed {
            Ok(())
        } else {
            Err(GatewayError::Forbidden(format!(
                "upstream host `{host}` is not permitted"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ranges() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
        ] {
            assert!(
                is_private_or_reserved(ip.parse().unwrap()),
                "{ip} should be blocked"
            );
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"] {
            assert!(
                !is_private_or_reserved(ip.parse().unwrap()),
                "{ip} should be allowed"
            );
        }
    }

    #[test]
    fn host_validation() {
        let config = HostValidationConfig {
            enabled: true,
            allowed_hosts: vec!["api.example.com".into(), "*.example.org".into()],
        };
        let mut headers = HeaderMap::new();
        headers.insert(HOST, "api.example.com:8080".parse().unwrap());
        assert!(validate_host(&headers, &config).is_ok());
        headers.insert(HOST, "a.example.org".parse().unwrap());
        assert!(validate_host(&headers, &config).is_ok());
        headers.insert(HOST, "evil.com".parse().unwrap());
        assert!(validate_host(&headers, &config).is_err());
    }

    #[tokio::test]
    async fn ssrf_guard_blocks_private_literal() {
        let guard = UpstreamGuard::new(true);
        assert!(guard.check("127.0.0.1", 80).await.is_err());
        assert!(guard.check("8.8.8.8", 80).await.is_ok());
    }
}
