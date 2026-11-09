//! 重定向地址与外部 URL 安全校验。

use url::Url;

use crate::shared::{AppError, AppResult};

/// 校验 OAuth 客户端重定向地址：必须与注册值完全匹配，且不允许片段。
pub fn parse_registered_redirect(candidate: &str, allow_http: bool) -> AppResult<Url> {
    let url = Url::parse(candidate)?;
    if url.fragment().is_some() {
        return Err(AppError::bad_request("redirect_uri 不允许包含 fragment"));
    }
    match url.scheme() {
        "https" => {}
        "http" if allow_http || is_loopback_host(url.host_str().unwrap_or_default()) => {}
        // 原生应用自定义 scheme 允许直接使用，但仍需与注册值精确匹配。
        _ => {}
    }
    Ok(url)
}

pub fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// 在发起服务端 HTTP 请求前校验目标 URL，避免 SSRF。
pub fn validate_external_url(candidate: &str, allow_http: bool) -> AppResult<Url> {
    let url = Url::parse(candidate)?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err(AppError::bad_request("仅支持 http/https 地址"));
    }
    if url.scheme() == "http" && !allow_http {
        return Err(AppError::bad_request("外部服务地址必须使用 HTTPS"));
    }
    if url.username() != "" || url.password().is_some() {
        return Err(AppError::bad_request("外部服务地址不允许内嵌凭据"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| AppError::bad_request("外部服务地址缺少主机名"))?;
    if is_loopback_host(host) || host.eq_ignore_ascii_case("0.0.0.0") {
        if !allow_http {
            return Err(AppError::bad_request("外部服务地址不允许指向本机"));
        }
        return Ok(url);
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_private_ip(&ip) && !allow_http {
            return Err(AppError::bad_request("外部服务地址不允许指向内网地址"));
        }
    } else if !allow_http {
        // 解析域名并拒绝内网解析结果，降低 DNS Rebinding 风险。
        use std::net::ToSocketAddrs;
        if let Ok(addrs) = (host, url.port_or_known_default().unwrap_or(443)).to_socket_addrs() {
            for addr in addrs {
                if is_private_ip(&addr.ip()) {
                    return Err(AppError::bad_request("外部服务地址解析到内网地址"));
                }
            }
        }
    }
    Ok(url)
}

fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1])
        }
        std::net::IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
        }
    }
}

/// 仅允许相对路径或配置中的可信来源作为登录后跳转目标，防止开放重定向。
pub fn safe_post_login_redirect(
    target: &str,
    allowed_origins: &[String],
    fallback: &str,
) -> String {
    if target.starts_with('/') && !target.starts_with("//") && !target.contains("\\") {
        return target.to_string();
    }
    if let Ok(url) = Url::parse(target) {
        let origin = url.origin().ascii_serialization();
        if allowed_origins.iter().any(|item| item == &origin) {
            return target.to_string();
        }
    }
    fallback.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_loopback_external_urls_in_production() {
        assert!(validate_external_url("https://127.0.0.1/token", false).is_err());
        assert!(validate_external_url("https://localhost/token", false).is_err());
        assert!(validate_external_url("http://example.com", false).is_err());
        assert!(validate_external_url("https://example.com", false).is_ok());
    }

    #[test]
    fn safe_redirect_blocks_absolute_untrusted_urls() {
        let fallback = "/";
        assert_eq!(
            safe_post_login_redirect("/dashboard", &[], fallback),
            "/dashboard"
        );
        assert_eq!(
            safe_post_login_redirect("//evil.example", &[], fallback),
            fallback
        );
        assert_eq!(
            safe_post_login_redirect("https://evil.example/x", &[], fallback),
            fallback
        );
        assert_eq!(
            safe_post_login_redirect(
                "https://app.example.com/cb",
                &["https://app.example.com".to_string()],
                fallback
            ),
            "https://app.example.com/cb"
        );
    }
}
