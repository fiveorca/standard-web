//! HTTP 协议相关的工具函数。

use std::net::IpAddr;

use http::header::{
    HeaderMap, HeaderName, CONNECTION, HOST, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::HeaderValue;

/// 判断是否为逐跳（hop-by-hop）请求头。
pub fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-connection"
    )
}

/// 收集 `Connection` 头中声明的、需要一并删除的扩展头名称。
fn connection_tokens(headers: &HeaderMap) -> Vec<HeaderName> {
    let mut names = Vec::new();
    if let Some(value) = headers.get(CONNECTION).and_then(|v| v.to_str().ok()) {
        for token in value.split(',') {
            let token = token.trim();
            if !token.is_empty() && token != "close" && token != "keep-alive" {
                if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
                    names.push(name);
                }
            }
        }
    }
    names
}

/// 删除逐跳头以及 `Connection` 中声明的扩展头。
pub fn remove_hop_by_hop(headers: &mut HeaderMap) {
    let extra = connection_tokens(headers);
    for name in extra {
        headers.remove(&name);
    }
    headers.remove(CONNECTION);
    headers.remove("keep-alive");
    headers.remove("proxy-authenticate");
    headers.remove("proxy-authorization");
    headers.remove(TE);
    headers.remove(TRAILER);
    headers.remove(TRANSFER_ENCODING);
    headers.remove(UPGRADE);
    headers.remove("proxy-connection");
}

/// 请求是否要求协议升级（WebSocket / h2c 等）。
pub fn wants_upgrade(headers: &HeaderMap) -> bool {
    let connection_upgrade = headers
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);
    connection_upgrade && headers.contains_key(UPGRADE)
}

/// 判断请求是否为 WebSocket 升级请求。
pub fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    wants_upgrade(headers)
        && headers
            .get(UPGRADE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
}

/// 计算请求头的总字节数，用于限制 Header 大小。
pub fn headers_size(headers: &HeaderMap) -> usize {
    headers
        .iter()
        .map(|(k, v)| k.as_str().len() + v.as_bytes().len() + 4)
        .sum()
}

/// 写入标准转发头。
///
/// `chain` 为可信代理链（从最早到最近），最后追加当前直连对端。
/// 网关会覆盖客户端传入的伪造值。
pub fn apply_forwarding_headers(
    headers: &mut HeaderMap,
    client_ip: Option<IpAddr>,
    original_host: Option<&str>,
    scheme: &str,
    peer: Option<IpAddr>,
) {
    let mut xff_parts: Vec<String> = Vec::new();
    if let Some(ip) = client_ip {
        xff_parts.push(ip.to_string());
    }
    if let Some(peer) = peer {
        let peer_str = peer.to_string();
        if !xff_parts.iter().any(|p| p == &peer_str) {
            xff_parts.push(peer_str);
        }
    }
    if !xff_parts.is_empty() {
        if let Ok(value) = HeaderValue::from_str(&xff_parts.join(", ")) {
            headers.insert("x-forwarded-for", value);
        }
    }

    if let Some(host) = original_host {
        if let Ok(value) = HeaderValue::from_str(host) {
            headers.insert("x-forwarded-host", value);
            headers.insert("x-forwarded-port", port_from_host(host));
        }
    }
    headers.insert(
        "x-forwarded-proto",
        HeaderValue::from_static(if scheme == "https" { "https" } else { "http" }),
    );

    let mut forwarded = String::new();
    if let Some(ip) = client_ip {
        forwarded.push_str(&format!("for=\"{ip}\""));
    }
    if let Some(host) = original_host {
        if !forwarded.is_empty() {
            forwarded.push(';');
        }
        forwarded.push_str(&format!("host=\"{host}\""));
    }
    if !forwarded.is_empty() {
        forwarded.push(';');
    }
    forwarded.push_str(&format!("proto={scheme}"));
    if let Ok(value) = HeaderValue::from_str(&forwarded) {
        headers.insert("forwarded", value);
    }
}

fn port_from_host(host: &str) -> HeaderValue {
    let port = if host.ends_with(":443") {
        "443"
    } else if let Some(idx) = host.rfind(':') {
        let candidate = &host[idx + 1..];
        if candidate.chars().all(|c| c.is_ascii_digit()) && !host.starts_with('[') {
            candidate
        } else if host.starts_with('[') && host.contains("]:") {
            host.rsplit(':').next().unwrap_or("80")
        } else {
            "80"
        }
    } else {
        "80"
    };
    HeaderValue::from_str(port).unwrap_or_else(|_| HeaderValue::from_static("80"))
}

/// 从 Host 头中提取主机名（不含端口）。
pub fn host_without_port(host: &str) -> &str {
    if let Some(stripped) = host.strip_prefix('[') {
        // IPv6: [::1]:8080
        return stripped.split(']').next().unwrap_or(stripped);
    }
    host.split(':').next().unwrap_or(host)
}

/// 检查 Host 是否合法（防止 Host 头攻击）。
pub fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 255 {
        return false;
    }
    !host
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '/' || c == '\\')
}

/// 判断响应状态码是否应当视为上游失败。
pub fn is_server_error(status: http::StatusCode) -> bool {
    status.is_server_error()
}

/// 判断 Host 头是否缺失。
pub fn is_host_missing(headers: &HeaderMap) -> bool {
    !headers.contains_key(HOST)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_hop_by_hop_and_connection_named_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, "keep-alive, X-Custom-Hop".parse().unwrap());
        headers.insert("x-custom-hop", "1".parse().unwrap());
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        headers.insert("x-keep", "yes".parse().unwrap());
        remove_hop_by_hop(&mut headers);
        assert!(!headers.contains_key("x-custom-hop"));
        assert!(!headers.contains_key("keep-alive"));
        assert!(headers.contains_key("x-keep"));
    }

    #[test]
    fn websocket_detection() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, "Upgrade".parse().unwrap());
        headers.insert(UPGRADE, "websocket".parse().unwrap());
        assert!(is_websocket_upgrade(&headers));
    }

    #[test]
    fn host_helpers() {
        assert_eq!(host_without_port("example.com:8080"), "example.com");
        assert_eq!(host_without_port("[::1]:8080"), "::1");
        assert!(valid_host("example.com"));
        assert!(!valid_host("bad host"));
    }
}
