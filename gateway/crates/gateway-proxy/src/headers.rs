//! HTTP Header 处理：Hop-by-Hop Header 清洗 + 代理链头管理。
//!
//! # Hop-by-Hop Header（RFC 7230 第 6.1 节）
//!
//! Hop-by-Hop headers 只对当前连接有意义，代理服务器不得转发它们。
//! 必须移除的固定列表：
//!
//!   - `Connection`          — 连接级选项
//!   - `Transfer-Encoding`   — HTTP/1.1 chunked，由代理重编码
//!   - `Keep-Alive`          — 连接保活参数
//!   - `Proxy-Authorization` — 代理认证
//!   - `Proxy-Authenticate`  — 代理认证（反向不适用）
//!   - `TE`                  — Transfer Encodings
//!   - `Trailer`             — 分块 Trailer
//!   - `Upgrade`             — 协议升级（WebSocket/SSE 暂时不支持）
//!   - `Proxy-Connection`    — 非标准但常见
//!   - `Alt-Svc`             — 替代服务
//!
//! 此外，`Connection` 头本身可能包含一个逗号分隔的 header 名称列表，
//! 指示这些 header 也应该被视为 hop-by-hop（例如 `Connection: close, X-Custom`）。
//! 我们必须额外移除 Connection 头中引用的所有 header。
//!
//! # 代理链头（Forwarded / X-Forwarded-For / X-Forwarded-Proto）
//!
//! 不能无条件信任客户端传来的值——恶意客户端可以伪造：
//!   ```text
//!   X-Forwarded-For: 1.2.3.4
//!   ```
//!
//! Phase 1 的简化策略：
//!   - 我们把客户端 IP **追加**到已有的 X-Forwarded-For 后面
//!   - X-Forwarded-Proto 如果没有就设为 "http"
//!   - 可信代理链在后续 Phase 2 的 security crate 中实现

use std::net::SocketAddr;

use http::HeaderMap;

/// Hop-by-Hop header 名称列表（小写）。
///
/// hyper 在内部处理 Transfer-Encoding，但我们还是明确移除一遍，
/// 防止某些 edge case（例如手动设置了 Transfer-Encoding: identity）。
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "transfer-encoding",
    "keep-alive",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "upgrade",
    "proxy-connection",
    "alt-svc",
];

/// 安全清理 HeaderMap：移除所有 Hop-by-Hop headers。
///
/// 参数：
/// - `headers`：需要清理的 HeaderMap（mut 引用，原地修改）
///
/// # 算法
///
/// 1. 先移除固定列表中的所有 Hop-by-Hop header
/// 2. 再检查 `Connection` header 是否引用了额外的 header 名称
///    （例如 `Connection: keep-alive, X-Custom-Header` 表示 X-Custom-Header
///     也是 hop-by-hop 的），一并移除
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // WebSocket / HTTP Upgrade：客户端显式要求协议升级时，必须保留
    // `Upgrade` 与 `Connection: upgrade` 两个头，否则 hyper client 不会
    // 发出升级请求，WebSocket 握手直接失败。
    let is_upgrade_request = headers.contains_key("upgrade")
        && headers
            .get("connection")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_ascii_lowercase().contains("upgrade"))
            .unwrap_or(false);

    // gRPC 依赖 `TE: trailers`（HTTP/2 中唯一允许的 TE 值），
    // 不能当作普通 hop-by-hop 头移除。
    let keep_te_trailers = headers
        .get("te")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().eq_ignore_ascii_case("trailers"))
        .unwrap_or(false);

    // 先收集 Connection 头引用的额外 header 名（可能多个 Connection 头）
    let mut extra_hop: Vec<String> = Vec::new();
    // hyper 1.x 的 get_all 直接返回 GetAll 迭代器（不是 Option）
    // 如果没有 Connection 头，GetAll 会是空迭代器
    let conn_values = headers.get_all("connection");
    for val in conn_values.iter() {
        let bytes = val.as_bytes();
        if let Ok(s) = std::str::from_utf8(bytes) {
            for name in s.split(',').map(|s| s.trim()) {
                if !name.is_empty() {
                    extra_hop.push(name.to_ascii_lowercase());
                }
            }
        }
    }

    // 移除固定列表 + Connection 引用的额外 headers
    let mut remove: Vec<String> = HOP_BY_HOP_HEADERS.iter().map(|s| s.to_string()).collect();
    remove.extend(extra_hop);

    for name in &remove {
        // 升级请求保留 Upgrade / Connection
        if is_upgrade_request && (name == "upgrade" || name == "connection") {
            continue;
        }
        // gRPC 保留 TE: trailers
        if keep_te_trailers && name == "te" {
            continue;
        }
        // HeaderMap::remove 大小写不敏感（HTTP header 名是 case-insensitive）
        headers.remove(name);
    }
}

/// 移除响应中的 Hop-by-Hop headers（从上游到客户端方向）。
///
/// 与 strip_hop_by_hop 完全相同的逻辑。响应和请求都需要清洗。
pub fn strip_response_hop_by_hop(headers: &mut HeaderMap) {
    strip_hop_by_hop(headers);
}

/// 注入代理链头：X-Forwarded-For / X-Forwarded-Proto / X-Forwarded-Host。
///
/// 参数：
/// - `headers`：要修改的请求头
/// - `client_ip`：从连接中拿到的客户端 socket 地址
/// - `scheme`：客户端请求使用的协议（Phase 1 固定 "http"，HTTPS 在 P1）
///
/// # 行为
///
/// - 如果 X-Forwarded-For 已存在，**追加** client_ip；不存在则创建
/// - X-Forwarded-Proto 不存在时设为 scheme
/// - X-Forwarded-Host 不存在时从 Host 头复制
pub fn inject_forwarded_headers(
    headers: &mut HeaderMap,
    client_ip: Option<SocketAddr>,
    scheme: &str,
) {
    if let Some(client_addr) = client_ip {
        let ip_str = client_addr.ip().to_string();
        // X-Forwarded-For 的值是逗号分隔的 IP 列表（代理链上每一跳都追加）
        if let Some(existing) = headers.get("x-forwarded-for").cloned() {
            // 已有 → 追加
            let existing_str = existing.as_bytes();
            // 组装新值："old-value, client_ip"
            // 用 HeaderValue 直接构造，避免转义问题
            let mut new_val = Vec::with_capacity(existing_str.len() + 2 + ip_str.len());
            new_val.extend_from_slice(existing_str);
            new_val.extend_from_slice(b", ");
            new_val.extend_from_slice(ip_str.as_bytes());
            if let Ok(val) = http::header::HeaderValue::from_bytes(&new_val) {
                headers.insert("x-forwarded-for", val);
            }
        } else {
            // 没有 → 创建
            if let Ok(val) = http::header::HeaderValue::from_str(&ip_str) {
                headers.insert("x-forwarded-for", val);
            }
        }
    }

    // X-Forwarded-Proto —— 只在不存在时设置，不覆盖已有的
    if !headers.contains_key("x-forwarded-proto") {
        if let Ok(val) = http::header::HeaderValue::from_str(scheme) {
            headers.insert("x-forwarded-proto", val);
        }
    }

    // X-Forwarded-Host —— 从 Host 头复制
    if !headers.contains_key("x-forwarded-host") {
        if let Some(host) = headers.get("host").cloned() {
            headers.insert("x-forwarded-host", host);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_removes_standard_hop_by_hop() {
        let mut h = HeaderMap::new();
        h.insert("connection", "keep-alive".parse().unwrap());
        h.insert("transfer-encoding", "chunked".parse().unwrap());
        h.insert("keep-alive", "timeout=60".parse().unwrap());
        h.insert("x-app", "v1".parse().unwrap());
        strip_hop_by_hop(&mut h);
        assert!(h.contains_key("x-app"), "custom header should survive");
        assert!(!h.contains_key("connection"));
        assert!(!h.contains_key("transfer-encoding"));
        assert!(!h.contains_key("keep-alive"));
    }

    #[test]
    fn strip_handles_connection_refs() {
        // Connection 头引用了非标准 header，也要移除
        let mut h = HeaderMap::new();
        h.insert("connection", "X-Custom-Header".parse().unwrap());
        h.insert("x-custom-header", "value".parse().unwrap());
        strip_hop_by_hop(&mut h);
        assert!(!h.contains_key("connection"));
        assert!(!h.contains_key("x-custom-header"));
    }

    #[test]
    fn inject_appends_to_existing_xff() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "10.0.0.1".parse().unwrap());
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        inject_forwarded_headers(&mut h, Some(addr), "http");
        let xff = h.get("x-forwarded-for").unwrap().to_str().unwrap();
        assert_eq!(xff, "10.0.0.1, 192.168.1.1");
    }

    #[test]
    fn inject_creates_xff_if_missing() {
        let mut h = HeaderMap::new();
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        inject_forwarded_headers(&mut h, Some(addr), "http");
        let xff = h.get("x-forwarded-for").unwrap().to_str().unwrap();
        assert_eq!(xff, "192.168.1.1");
    }

    #[test]
    fn inject_ignores_if_no_client_ip() {
        let mut h = HeaderMap::new();
        inject_forwarded_headers(&mut h, None, "http");
        assert!(!h.contains_key("x-forwarded-for"));
    }
}
