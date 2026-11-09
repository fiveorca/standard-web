//! 本地响应缓存。
//!
//! 只缓存安全的 GET / HEAD 响应，并严格遵守缓存安全语义：带 `Set-Cookie`、
//! `Cache-Control: private/no-store`、或带 Authorization 的私有响应默认不缓存。
//! 大响应、未知长度的流式响应自动绕过缓存。

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use http::header::{
    HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CACHE_CONTROL, COOKIE, SET_COOKIE,
};
use http::{Method, StatusCode};
use moka::future::Cache;

use crate::config::model::{GlobalCacheConfig, RouteCacheConfig};
use crate::core::identity::Identity;
use crate::utils::http::is_hop_by_hop;

/// 缓存中的响应。
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub status: StatusCode,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Bytes,
    pub stored_at: Instant,
}

/// 生效的缓存策略。
#[derive(Debug, Clone)]
pub struct CachePolicy {
    pub ttl: Duration,
    pub max_capacity: u64,
    pub key_template: Option<String>,
    pub cacheable_status: Vec<u16>,
    pub max_body_size: usize,
    pub cache_authenticated: bool,
    pub vary_headers: Vec<String>,
    pub respect_cache_control: bool,
}

impl CachePolicy {
    pub fn from_route(config: &RouteCacheConfig) -> Self {
        Self {
            ttl: config.ttl,
            max_capacity: config.max_capacity,
            key_template: config.key_template.clone(),
            cacheable_status: config.cacheable_status.clone(),
            max_body_size: config.max_body_size,
            cache_authenticated: config.cache_authenticated,
            vary_headers: config.vary_headers.clone(),
            respect_cache_control: config.respect_cache_control,
        }
    }

    pub fn from_global(config: &GlobalCacheConfig) -> Self {
        Self {
            ttl: config.default_ttl,
            max_capacity: config.max_capacity,
            key_template: None,
            cacheable_status: config.cacheable_status.clone(),
            max_body_size: config.max_body_size,
            cache_authenticated: config.cache_authenticated,
            vary_headers: Vec::new(),
            respect_cache_control: config.respect_cache_control,
        }
    }
}

/// 请求是否适合查询/写入缓存。
pub fn request_cacheable(
    policy: &CachePolicy,
    method: &Method,
    headers: &HeaderMap,
    identity: Option<&Identity>,
) -> bool {
    if method != Method::GET && method != Method::HEAD {
        return false;
    }
    if headers.contains_key("upgrade") {
        return false;
    }
    if headers.contains_key(AUTHORIZATION) && !policy.cache_authenticated {
        return false;
    }
    if identity.is_some() && !policy.cache_authenticated {
        return false;
    }
    if policy.respect_cache_control {
        if let Some(value) = headers.get(CACHE_CONTROL).and_then(|v| v.to_str().ok()) {
            let lower = value.to_ascii_lowercase();
            if lower.contains("no-store") || lower.contains("no-cache") {
                return false;
            }
        }
    }
    true
}

/// 响应是否允许写入缓存。
pub fn response_cacheable(
    policy: &CachePolicy,
    status: StatusCode,
    headers: &HeaderMap,
    body_len: usize,
) -> bool {
    if !policy.cacheable_status.contains(&status.as_u16()) {
        return false;
    }
    if body_len > policy.max_body_size {
        return false;
    }
    if headers.contains_key(SET_COOKIE) {
        return false;
    }
    if policy.respect_cache_control {
        if let Some(value) = headers.get(CACHE_CONTROL).and_then(|v| v.to_str().ok()) {
            let lower = value.to_ascii_lowercase();
            if lower.contains("no-store") || lower.contains("private") {
                return false;
            }
        }
    }
    true
}

/// 构造缓存 Key。
pub fn cache_key(
    policy: &CachePolicy,
    route_id: &str,
    method: &Method,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
    identity: Option<&Identity>,
) -> String {
    if let Some(template) = &policy.key_template {
        let custom =
            resolve_template(template, headers, query).unwrap_or_else(|| "default".to_string());
        return format!("{route_id}|{custom}");
    }
    let mut key = format!(
        "{}|{}|{}|{}",
        route_id,
        method.as_str(),
        path,
        query.unwrap_or("")
    );
    if policy.cache_authenticated {
        if let Some(identity) = identity {
            key.push('|');
            key.push_str(&identity.subject);
        }
    }
    for name in &policy.vary_headers {
        key.push('|');
        if let Some(value) = headers.get(name.as_str()).and_then(|v| v.to_str().ok()) {
            key.push_str(&name.to_ascii_lowercase());
            key.push('=');
            key.push_str(value);
        }
    }
    key
}

fn resolve_template(template: &str, headers: &HeaderMap, query: Option<&str>) -> Option<String> {
    if let Some(name) = template.strip_prefix("header:") {
        return headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());
    }
    if let Some(name) = template.strip_prefix("query:") {
        let query = query?;
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            if k == name {
                return Some(v.to_string());
            }
        }
        return None;
    }
    if let Some(name) = template.strip_prefix("cookie:") {
        let cookies = headers.get(COOKIE)?.to_str().ok()?;
        for part in cookies.split(';') {
            let (k, v) = part.trim().split_once('=')?;
            if k == name {
                return Some(v.to_string());
            }
        }
        return None;
    }
    template
        .strip_prefix("literal:")
        .map(|v| v.to_string())
        .or_else(|| Some(template.to_string()))
}

struct RouteCache {
    cache: Cache<String, Arc<CachedResponse>>,
}

/// 响应缓存注册表：每个路由按 TTL / 容量独立成池。
#[derive(Default)]
pub struct ResponseCache {
    caches: DashMap<String, Arc<RouteCache>>,
}

impl ResponseCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn cache_for(&self, route_id: &str, policy: &CachePolicy) -> Arc<RouteCache> {
        let fingerprint = format!(
            "{}:{}:{}",
            route_id,
            policy.ttl.as_millis(),
            policy.max_capacity
        );
        if let Some(entry) = self.caches.get(&fingerprint) {
            return entry.clone();
        }
        // 配置变化时清理该路由的旧缓存池。
        self.caches
            .retain(|key, _| !key.starts_with(&format!("{route_id}:")));
        let cache = Cache::builder()
            .max_capacity(policy.max_capacity.max(1))
            .time_to_live(policy.ttl)
            .build();
        let entry = Arc::new(RouteCache { cache });
        self.caches.insert(fingerprint, entry.clone());
        entry
    }

    pub async fn get(
        &self,
        route_id: &str,
        policy: &CachePolicy,
        key: &str,
    ) -> Option<Arc<CachedResponse>> {
        self.cache_for(route_id, policy).cache.get(key).await
    }

    pub async fn put(
        &self,
        route_id: &str,
        policy: &CachePolicy,
        key: String,
        status: StatusCode,
        headers: &HeaderMap,
        body: Bytes,
    ) {
        let stored_headers = headers
            .iter()
            .filter(|(name, _)| {
                !is_hop_by_hop(name)
                    && name.as_str() != "content-length"
                    && name.as_str() != "age"
                    && name.as_str() != "x-cache"
            })
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let entry = Arc::new(CachedResponse {
            status,
            headers: stored_headers,
            body,
            stored_at: Instant::now(),
        });
        self.cache_for(route_id, policy)
            .cache
            .insert(key, entry)
            .await;
    }

    pub fn purge_route(&self, route_id: &str) {
        let prefix = format!("{route_id}:");
        self.caches.retain(|key, cache| {
            if key.starts_with(&prefix) {
                cache.cache.invalidate_all();
                false
            } else {
                true
            }
        });
    }

    pub fn purge_all(&self) {
        for entry in self.caches.iter() {
            entry.value().cache.invalidate_all();
        }
        self.caches.clear();
    }

    pub fn entry_count(&self) -> u64 {
        self.caches
            .iter()
            .map(|entry| entry.value().cache.entry_count())
            .sum()
    }

    pub fn route_count(&self) -> usize {
        self.caches.len()
    }
}

/// 把缓存条目转换为响应。
pub fn cached_response(entry: &CachedResponse) -> http::Response<axum::body::Body> {
    let mut response = http::Response::builder().status(entry.status);
    if let Some(headers) = response.headers_mut() {
        for (name, value) in &entry.headers {
            headers.append(name.clone(), value.clone());
        }
        headers.insert(
            HeaderName::from_static("x-cache"),
            HeaderValue::from_static("HIT"),
        );
        let age = entry.stored_at.elapsed().as_secs();
        if let Ok(value) = HeaderValue::from_str(&age.to_string()) {
            headers.insert(HeaderName::from_static("age"), value);
        }
    }
    response
        .body(axum::body::Body::from(entry.body.clone()))
        .unwrap_or_else(|_| {
            http::Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::empty())
                .expect("valid response")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> CachePolicy {
        CachePolicy {
            ttl: Duration::from_secs(10),
            max_capacity: 100,
            key_template: None,
            cacheable_status: vec![200],
            max_body_size: 1024,
            cache_authenticated: false,
            vary_headers: vec!["accept-language".into()],
            respect_cache_control: true,
        }
    }

    #[test]
    fn authorization_bypasses_cache() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer token".parse().unwrap());
        assert!(!request_cacheable(&policy(), &Method::GET, &headers, None));
    }

    #[test]
    fn no_store_and_private_are_not_cached() {
        let p = policy();
        let mut headers = HeaderMap::new();
        headers.insert(CACHE_CONTROL, "no-store".parse().unwrap());
        assert!(!response_cacheable(&p, StatusCode::OK, &headers, 10));
        headers.insert(CACHE_CONTROL, "private, max-age=60".parse().unwrap());
        assert!(!response_cacheable(&p, StatusCode::OK, &headers, 10));
        headers.insert(CACHE_CONTROL, "public, max-age=60".parse().unwrap());
        assert!(response_cacheable(&p, StatusCode::OK, &headers, 10));
    }

    #[test]
    fn set_cookie_is_not_cached() {
        let mut headers = HeaderMap::new();
        headers.insert(SET_COOKIE, "session=1".parse().unwrap());
        assert!(!response_cacheable(&policy(), StatusCode::OK, &headers, 10));
    }

    #[tokio::test]
    async fn round_trip() {
        let cache = ResponseCache::new();
        let p = policy();
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/plain".parse().unwrap());
        cache
            .put(
                "r",
                &p,
                "k".into(),
                StatusCode::OK,
                &headers,
                Bytes::from_static(b"hello"),
            )
            .await;
        let hit = cache.get("r", &p, "k").await.unwrap();
        assert_eq!(hit.body, Bytes::from_static(b"hello"));
        let response = cached_response(&hit);
        assert_eq!(response.headers().get("x-cache").unwrap(), "HIT");
    }
}
