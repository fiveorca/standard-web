//! CORS：全局与路由级跨域策略，正确处理 OPTIONS 预检。

use http::header::{
    HeaderMap, HeaderName, HeaderValue, ACCESS_CONTROL_ALLOW_CREDENTIALS,
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_HEADERS,
    ACCESS_CONTROL_REQUEST_METHOD, ORIGIN, VARY,
};
use http::Method;
use regex::Regex;

use crate::config::model::CorsConfig;
use crate::utils::pattern::glob_to_regex;

enum OriginMatcher {
    Any,
    Exact(String),
    Pattern(Regex),
}

/// 编译后的 CORS 策略。
pub struct CorsPolicy {
    origins: Vec<OriginMatcher>,
    methods: Vec<String>,
    headers: Vec<String>,
    exposed: Vec<String>,
    credentials: bool,
    max_age: u64,
}

impl CorsPolicy {
    pub fn new(config: &CorsConfig) -> Result<Self, String> {
        let mut origins = Vec::with_capacity(config.allowed_origins.len());
        for origin in &config.allowed_origins {
            if origin == "*" {
                origins.push(OriginMatcher::Any);
            } else if origin.contains('*') {
                let regex = Regex::new(&glob_to_regex(&origin.to_ascii_lowercase()))
                    .map_err(|e| format!("invalid CORS origin pattern `{origin}`: {e}"))?;
                origins.push(OriginMatcher::Pattern(regex));
            } else {
                origins.push(OriginMatcher::Exact(origin.clone()));
            }
        }
        Ok(Self {
            origins,
            methods: config.allowed_methods.clone(),
            headers: config.allowed_headers.clone(),
            exposed: config.exposed_headers.clone(),
            credentials: config.allow_credentials,
            max_age: config.max_age.as_secs(),
        })
    }

    fn origin_allowed(&self, origin: &str) -> bool {
        let lower = origin.to_ascii_lowercase();
        self.origins.iter().any(|matcher| match matcher {
            OriginMatcher::Any => true,
            OriginMatcher::Exact(value) => value.eq_ignore_ascii_case(origin),
            OriginMatcher::Pattern(regex) => regex.is_match(&lower),
        })
    }

    fn is_wildcard(&self) -> bool {
        self.origins.len() == 1 && matches!(self.origins[0], OriginMatcher::Any)
    }

    fn requested_headers(&self, headers: &HeaderMap) -> Option<String> {
        if self.headers.iter().any(|h| h == "*") {
            return headers
                .get(ACCESS_CONTROL_REQUEST_HEADERS)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.to_string());
        }
        if self.headers.is_empty() {
            return None;
        }
        Some(self.headers.join(", "))
    }

    /// 写入实际请求的 CORS 响应头。
    pub fn apply(&self, request_headers: &HeaderMap, response_headers: &mut HeaderMap) {
        let origin = match request_headers.get(ORIGIN).and_then(|v| v.to_str().ok()) {
            Some(origin) => origin,
            None => return,
        };
        if !self.origin_allowed(origin) {
            return;
        }
        let allow_origin = if self.is_wildcard() && !self.credentials {
            "*".to_string()
        } else {
            origin.to_string()
        };
        if let Ok(value) = HeaderValue::from_str(&allow_origin) {
            response_headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, value);
        }
        append_vary(response_headers, "Origin");
        if self.credentials {
            response_headers.insert(
                ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
        if !self.exposed.is_empty() {
            if let Ok(value) = HeaderValue::from_str(&self.exposed.join(", ")) {
                response_headers.insert(ACCESS_CONTROL_EXPOSE_HEADERS, value);
            }
        }
    }

    /// 处理预检请求；返回 `Some(response)` 表示请求已被 CORS 处理。
    pub fn preflight(
        &self,
        request_headers: &HeaderMap,
        method: &Method,
    ) -> Option<http::Response<axum::body::Body>> {
        if method != Method::OPTIONS {
            return None;
        }
        let origin = request_headers.get(ORIGIN).and_then(|v| v.to_str().ok())?;
        let request_method = request_headers
            .get(ACCESS_CONTROL_REQUEST_METHOD)
            .and_then(|v| v.to_str().ok())?;
        if !self.origin_allowed(origin) {
            return Some(no_content_response(false));
        }
        if !self
            .methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(request_method))
        {
            return Some(no_content_response(false));
        }

        let mut response = http::Response::builder().status(http::StatusCode::NO_CONTENT);
        {
            let headers = response.headers_mut().expect("headers");
            let allow_origin = if self.is_wildcard() && !self.credentials {
                "*".to_string()
            } else {
                origin.to_string()
            };
            if let Ok(value) = HeaderValue::from_str(&allow_origin) {
                headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, value);
            }
            append_vary(headers, "Origin");
            append_vary(headers, "Access-Control-Request-Method");
            append_vary(headers, "Access-Control-Request-Headers");
            if self.credentials {
                headers.insert(
                    ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    HeaderValue::from_static("true"),
                );
            }
            if let Ok(value) = HeaderValue::from_str(&self.methods.join(", ")) {
                headers.insert(ACCESS_CONTROL_ALLOW_METHODS, value);
            }
            if let Some(requested) = self.requested_headers(request_headers) {
                if let Ok(value) = HeaderValue::from_str(&requested) {
                    headers.insert(ACCESS_CONTROL_ALLOW_HEADERS, value);
                }
            }
            if let Ok(value) = HeaderValue::from_str(&self.max_age.to_string()) {
                headers.insert(ACCESS_CONTROL_MAX_AGE, value);
            }
        }
        Some(
            response
                .body(axum::body::Body::empty())
                .unwrap_or_else(|_| no_content_response(true)),
        )
    }
}

fn no_content_response(with_allow_origin: bool) -> http::Response<axum::body::Body> {
    let mut response = http::Response::builder()
        .status(http::StatusCode::NO_CONTENT)
        .body(axum::body::Body::empty())
        .expect("valid response");
    if !with_allow_origin {
        response
            .headers_mut()
            .insert(VARY, HeaderValue::from_static("Origin"));
    }
    response
}

fn append_vary(headers: &mut HeaderMap, value: &str) {
    let name = HeaderName::from_static("vary");
    if let Some(existing) = headers.get(&name).and_then(|v| v.to_str().ok()) {
        if existing
            .split(',')
            .any(|v| v.trim().eq_ignore_ascii_case(value))
        {
            return;
        }
        let combined = format!("{existing}, {value}");
        if let Ok(header) = HeaderValue::from_str(&combined) {
            headers.insert(name, header);
        }
    } else if let Ok(header) = HeaderValue::from_str(value) {
        headers.insert(name, header);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CorsConfig {
        CorsConfig {
            allowed_origins: vec!["https://app.example.com".into()],
            allowed_methods: vec!["GET".into(), "POST".into()],
            allowed_headers: vec!["content-type".into(), "x-token".into()],
            exposed_headers: vec!["x-request-id".into()],
            allow_credentials: true,
            ..Default::default()
        }
    }

    #[test]
    fn preflight_echoes_origin() {
        let policy = CorsPolicy::new(&config()).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, "https://app.example.com".parse().unwrap());
        headers.insert(ACCESS_CONTROL_REQUEST_METHOD, "POST".parse().unwrap());
        let response = policy.preflight(&headers, &Method::OPTIONS).unwrap();
        assert_eq!(response.status(), http::StatusCode::NO_CONTENT);
        assert_eq!(
            response
                .headers()
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .to_str()
                .unwrap(),
            "https://app.example.com"
        );
        assert_eq!(
            response
                .headers()
                .get(ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .unwrap()
                .to_str()
                .unwrap(),
            "true"
        );
    }

    #[test]
    fn disallowed_origin_gets_no_cors_headers() {
        let policy = CorsPolicy::new(&config()).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, "https://evil.example.com".parse().unwrap());
        let mut response_headers = HeaderMap::new();
        policy.apply(&headers, &mut response_headers);
        assert!(!response_headers.contains_key(ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    #[test]
    fn wildcard_without_credentials_uses_star() {
        let policy = CorsPolicy::new(&CorsConfig::default()).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, "https://any.example.com".parse().unwrap());
        let mut response_headers = HeaderMap::new();
        policy.apply(&headers, &mut response_headers);
        assert_eq!(
            response_headers
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .to_str()
                .unwrap(),
            "*"
        );
    }
}
