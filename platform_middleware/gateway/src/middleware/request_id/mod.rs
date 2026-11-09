//! 请求 ID 与追踪 ID 注入。

use http::HeaderMap;

use crate::utils::new_request_id;

/// 解析请求 ID：客户端提供的合法 ID 可复用（受配置控制），否则生成新的 UUID。
pub fn resolve_request_id(headers: &HeaderMap, header_name: &str, trust_client: bool) -> String {
    let candidate = if trust_client {
        headers.get(header_name).and_then(|v| v.to_str().ok())
    } else {
        None
    };
    new_request_id(candidate)
}

/// 写入请求 ID 响应头。
pub fn set_request_id(headers: &mut HeaderMap, header_name: &str, request_id: &str) {
    if let (Ok(name), Ok(value)) = (
        http::HeaderName::from_bytes(header_name.as_bytes()),
        http::HeaderValue::from_str(request_id),
    ) {
        headers.insert(name, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuses_valid_client_id() {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", "abc-123".parse().unwrap());
        assert_eq!(
            resolve_request_id(&headers, "x-request-id", true),
            "abc-123"
        );
        assert_ne!(
            resolve_request_id(&headers, "x-request-id", false),
            "abc-123"
        );
    }

    #[test]
    fn rejects_unsafe_client_id() {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", "bad id".parse().unwrap());
        assert_ne!(resolve_request_id(&headers, "x-request-id", true), "bad id");
    }
}
