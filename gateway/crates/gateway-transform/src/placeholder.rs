//! 占位符替换：`${request_id}` / `${client_ip}` / `${method}` 等。
//!
//! # 支持的占位符
//!
//! | 占位符 | 来源 | 说明 |
//! |---|---|---|
//! | `${request_id}` | `env.request_id` | 请求 ID |
//! | `${client_ip}` | `env.client_ip` | 客户端地址（进程内调用可能缺失） |
//! | `${method}` | `env.method` | HTTP 方法 |
//! | `${path}` | `env.uri.path()` | 请求路径 |
//! | `${protocol}` | `env.version` | HTTP 版本 |
//! | `${host}` | `env.uri.host()` 或 Host header | 主机名 |
//! | `${header:<name>}` | `env.request_headers.get(name)` | 指定请求头值 |
//!
//! # 缺失值处理
//!   - `client_ip` 可能为 None（进程内调用）
//!   - 指定 Header 可能不存在
//!   - 这些占位符**不替换**，原样保留 `${xxx}` —— 让调用方看到
//!     "配置引用了不存在的东西"，方便调试，而不是静默出空值。
//!
//! # 格式安全
//!   - Header 名会被规范化为小写（`HeaderName` 的行为）
//!   - Header 值在替换前会做 CR/LF/NUL 检查（注入防护）

use std::net::SocketAddr;

use http::header::{HeaderName, HOST};
use http::{HeaderMap, Method, Uri, Version};

/// 占位符替换所需的最小环境视图。
///
/// 与 `gateway-plugin::PluginContext` 解耦：`apply` 需要在持有
/// `response.headers` 可变借用时执行，但那个借用阻止了对 `&PluginContext`
/// 的不可变借用。把需要的字段抽出来组装成这个轻量结构，让 apply
/// 只需依赖 `&PlaceholderEnv`，不再间接依赖 `&PluginContext`。
#[derive(Debug, Clone)]
pub struct PlaceholderEnv {
    pub request_id: String,
    pub client_ip: Option<SocketAddr>,
    pub method: Method,
    pub uri: Uri,
    pub version: Version,
    pub request_headers: HeaderMap,
}

impl PlaceholderEnv {
    /// 从 PluginContext 组装环境视图。
    ///
    /// 这是唯一一个与 PluginContext 交互的点；之后 `apply` / `render`
    /// 都只依赖 `&PlaceholderEnv`，借用冲突的边界得以清晰。
    pub fn from_plugin_ctx(ctx: &gateway_plugin::PluginContext<'_>) -> Self {
        Self {
            request_id: ctx.request_id().to_string(),
            client_ip: ctx.client_ip(),
            method: ctx.parts.method.clone(),
            uri: ctx.parts.uri.clone(),
            version: ctx.parts.version,
            request_headers: ctx.parts.headers.clone(),
        }
    }
}

/// 在模板字符串中执行占位符替换。
///
/// 参数：
/// - `template`：原始模板（例如 `"${request_id}-${client_ip}"`）
/// - `env`：占位符环境（请求视图的最小快照）
///
/// 返回替换后的字符串；缺失值的占位符原样保留。
pub fn render(template: &str, env: &PlaceholderEnv) -> String {
    let mut result = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // 寻找下一个 `${`
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            // 找闭合的 `}`
            let start = i + 2;
            let mut end = None;
            for (j, &b) in bytes.iter().enumerate().skip(start) {
                if b == b'}' {
                    end = Some(j);
                    break;
                }
            }

            match end {
                Some(end) => {
                    let key = &template[start..end];
                    // 替换；缺失值保留原样
                    let replacement = lookup(key, env);
                    if let Some(repl) = replacement {
                        result.push_str(&repl);
                    } else {
                        // 原样保留：让调用方看到"引用了不存在的值"
                        result.push_str("${");
                        result.push_str(key);
                        result.push('}');
                    }
                    i = end + 1;
                },
                // 没有闭合 `}`：`${` 作为普通字符保留
                None => {
                    result.push_str("${");
                    i += 2;
                },
            }
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }

    result
}

/// 按 key 查找占位符值。
fn lookup(key: &str, env: &PlaceholderEnv) -> Option<String> {
    match key {
        "request_id" => Some(env.request_id.clone()),
        "client_ip" => env.client_ip.map(|addr| addr.ip().to_string()),
        "method" => Some(env.method.as_str().to_string()),
        "path" => Some(env.uri.path().to_string()),
        "protocol" => Some(format!("{:?}", env.version)),
        "host" => {
            // 优先 URI.host，再看 Host header
            if let Some(host) = env.uri.host() {
                Some(host.to_string())
            } else {
                env.request_headers.get(HOST).and_then(|v| v.to_str().ok()).map(str::to_string)
            }
        },
        // `${header:name}` —— 冒号分隔
        rest if rest.starts_with("header:") => {
            let header_name = rest.trim_start_matches("header:");
            // HeaderName::from_bytes 会拒绝非法字符
            let name = HeaderName::from_bytes(header_name.as_bytes()).ok()?;
            env.request_headers.get(&name).and_then(|v| v.to_str().ok()).map(str::to_string)
        },
        // 未知 key：返回 None（占位符原样保留）
        _ => None,
    }
}

/// Header 值安全检查：拒绝 CR / LF / NUL（Header 注入防护）。
///
/// 参数：
/// - `value`：要写入 Header 的值（可能经过占位符替换）
///
/// 返回：
/// - `Ok(HeaderValue)`：合法，可安全写入
/// - `Err(reason)`：非法字符存在
pub fn sanitize_header_value(value: &str) -> Result<http::HeaderValue, String> {
    if value.contains('\r') {
        return Err("header value must not contain CR".into());
    }
    if value.contains('\n') {
        return Err("header value must not contain LF".into());
    }
    if value.contains('\0') {
        return Err("header value must not contain NUL".into());
    }
    http::HeaderValue::from_str(value).map_err(|e| format!("invalid header value: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    /// 辅助：构造 PlaceholderEnv
    fn make_env() -> PlaceholderEnv {
        PlaceholderEnv {
            request_id: "req-abc".into(),
            client_ip: Some("10.0.0.1:1234".parse().expect("addr")),
            method: http::Method::GET,
            uri: "https://example.com/api/users?q=42".parse().expect("uri"),
            version: http::Version::HTTP_11,
            request_headers: HeaderMap::new(),
        }
    }

    /// 基本占位符正确替换
    #[test]
    fn basic_placeholders() {
        let env = make_env();

        assert_eq!(render("${request_id}", &env), "req-abc");
        assert_eq!(render("${client_ip}", &env), "10.0.0.1");
        assert_eq!(render("${method}", &env), "GET");
        assert_eq!(render("${path}", &env), "/api/users");
        assert_eq!(render("${host}", &env), "example.com");
    }

    /// header:name 占位符
    #[test]
    fn header_placeholder() {
        let mut env = make_env();
        env.request_headers
            .insert(HeaderName::from_static("x-user-id"), http::HeaderValue::from_static("alice"));

        assert_eq!(render("user=${header:x-user-id}", &env), "user=alice");
        // Header 不存在 → 原样保留
        assert_eq!(render("${header:x-missing}", &env), "${header:x-missing}");
    }

    /// 缺失的占位符原样保留（不是空字符串）
    #[test]
    fn missing_placeholder_kept_as_is() {
        let mut env = make_env();
        env.client_ip = None;

        assert_eq!(render("ip=${client_ip}", &env), "ip=${client_ip}");
    }

    /// 非占位符文本原样保留
    #[test]
    fn literal_text_preserved() {
        let env = make_env();

        assert_eq!(render("static-value", &env), "static-value");
        assert_eq!(render("before-${request_id}-after", &env), "before-req-abc-after");
    }

    /// Header 值安全检查：拒绝注入字符
    #[test]
    fn sanitize_rejects_crlf_and_nul() {
        assert!(sanitize_header_value("good").is_ok());
        assert!(sanitize_header_value("bad\rvalue").is_err());
        assert!(sanitize_header_value("bad\nvalue").is_err());
        assert!(sanitize_header_value("bad\0value").is_err());
    }
}
