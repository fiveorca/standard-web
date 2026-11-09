//! Cookie 构造与解析（认证会话、CSRF Token）。

use axum::http::{header, HeaderMap, HeaderValue};

use crate::config::Settings;

pub const CSRF_COOKIE: &str = "auth_csrf";

pub fn header_value(cookie: String) -> HeaderValue {
    HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static(""))
}

pub fn build_cookie(
    name: &str,
    value: &str,
    max_age_secs: Option<u64>,
    secure: bool,
    domain: Option<&str>,
    same_site: &str,
    http_only: bool,
) -> String {
    let mut cookie = format!("{name}={value}; Path=/; SameSite={same_site}");
    if http_only {
        cookie.push_str("; HttpOnly");
    }
    if secure {
        cookie.push_str("; Secure");
    }
    if let Some(max_age) = max_age_secs {
        cookie.push_str(&format!("; Max-Age={max_age}"));
    }
    if let Some(domain) = domain {
        if !domain.is_empty() {
            cookie.push_str(&format!("; Domain={domain}"));
        }
    }
    cookie
}

pub fn session_cookie(settings: &Settings, token: &str) -> String {
    build_cookie(
        &settings.security.cookie_name,
        token,
        Some(settings.security.session_ttl_secs),
        settings.security.cookie_secure,
        settings.security.cookie_domain.as_deref(),
        &settings.security.cookie_same_site,
        true,
    )
}

pub fn csrf_cookie(settings: &Settings, token: &str) -> String {
    build_cookie(
        CSRF_COOKIE,
        token,
        Some(settings.security.session_ttl_secs),
        settings.security.cookie_secure,
        settings.security.cookie_domain.as_deref(),
        &settings.security.cookie_same_site,
        false,
    )
}

pub fn clear_session_cookie(settings: &Settings) -> String {
    build_cookie(
        &settings.security.cookie_name,
        "",
        Some(0),
        settings.security.cookie_secure,
        settings.security.cookie_domain.as_deref(),
        &settings.security.cookie_same_site,
        true,
    )
}

pub fn clear_csrf_cookie(settings: &Settings) -> String {
    build_cookie(
        CSRF_COOKIE,
        "",
        Some(0),
        settings.security.cookie_secure,
        settings.security.cookie_domain.as_deref(),
        &settings.security.cookie_same_site,
        false,
    )
}

pub fn cookie_from_headers(headers: &HeaderMap, name: &str) -> Option<String> {
    let header = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in header.split(';') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            if key.trim() == name {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

pub fn bearer_from_headers(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn parses_cookies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; auth_session=token-value; b=2"),
        );
        assert_eq!(
            cookie_from_headers(&headers, "auth_session"),
            Some("token-value".to_string())
        );
        assert_eq!(cookie_from_headers(&headers, "missing"), None);
    }

    #[test]
    fn parses_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer abc.def.ghi"),
        );
        assert_eq!(
            bearer_from_headers(&headers),
            Some("abc.def.ghi".to_string())
        );
    }

    #[test]
    fn builds_secure_cookie() {
        let cookie = build_cookie("s", "v", Some(60), true, None, "Lax", true);
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("Max-Age=60"));
    }
}
