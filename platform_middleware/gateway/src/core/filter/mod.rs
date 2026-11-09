//! 网关过滤器（Gateway Filter / Global Filter）。
//!
//! 过滤器分为请求阶段和响应阶段：
//! - 请求阶段可以修改请求路径、查询参数、请求头；
//! - 响应阶段可以修改响应头（响应体始终流式转发，不做缓冲）。
//!
//! 所有内置过滤器都实现了 [`GatewayFilter`] trait，第三方可以通过
//! [`FilterRegistry::register`] 注册自定义过滤器。

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::Method;
use once_cell::sync::Lazy;
use regex::Regex;

use crate::config::model::{FilterObject, FilterSpec};
use crate::core::identity::Identity;
use crate::error::{GatewayError, Result};

/// 请求阶段过滤器上下文。
pub struct FilterRequest<'a> {
    pub method: &'a Method,
    pub path: String,
    pub query: Option<String>,
    pub headers: &'a mut HeaderMap,
    pub identity: Option<&'a Identity>,
    pub metadata: &'a HashMap<String, String>,
    /// 是否保留客户端原始 Host 头。
    pub preserve_host: bool,
}

impl FilterRequest<'_> {
    pub fn set_path(&mut self, path: impl Into<String>) {
        self.path = path.into();
    }
}

/// 响应阶段过滤器上下文。
pub struct FilterResponse<'a> {
    pub status: http::StatusCode,
    pub headers: &'a mut HeaderMap,
    pub route_id: &'a str,
}

/// 网关过滤器。
#[async_trait]
pub trait GatewayFilter: Send + Sync {
    /// 过滤器名称。
    fn name(&self) -> &'static str;
    /// 执行顺序，数值越小越先执行；相同顺序按配置顺序执行。
    fn order(&self) -> i32 {
        100
    }
    /// 请求阶段。
    async fn apply_request(&self, _ctx: &mut FilterRequest<'_>) -> Result<()> {
        Ok(())
    }
    /// 响应阶段。
    fn apply_response(&self, _ctx: &mut FilterResponse<'_>) -> Result<()> {
        Ok(())
    }
}

/// 全局过滤器：对所有路由生效。
#[async_trait]
pub trait GlobalFilter: Send + Sync {
    fn name(&self) -> &'static str;
    fn order(&self) -> i32 {
        0
    }
    async fn apply_request(&self, _ctx: &mut FilterRequest<'_>) -> Result<()> {
        Ok(())
    }
    fn apply_response(&self, _ctx: &mut FilterResponse<'_>) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 内置过滤器
// ---------------------------------------------------------------------------

/// 去除路径前缀。
#[derive(Debug)]
pub struct StripPrefixFilter {
    pub parts: usize,
}

#[async_trait]
impl GatewayFilter for StripPrefixFilter {
    fn name(&self) -> &'static str {
        "StripPrefix"
    }
    async fn apply_request(&self, ctx: &mut FilterRequest<'_>) -> Result<()> {
        let segments: Vec<&str> = ctx.path.split('/').filter(|s| !s.is_empty()).collect();
        let remaining: Vec<&str> = segments.iter().skip(self.parts).copied().collect();
        let mut path = String::new();
        for seg in remaining {
            path.push('/');
            path.push_str(seg);
        }
        if path.is_empty() {
            path.push('/');
        }
        ctx.set_path(path);
        Ok(())
    }
}

/// 添加路径前缀。
#[derive(Debug)]
pub struct PrefixPathFilter {
    pub prefix: String,
}

#[async_trait]
impl GatewayFilter for PrefixPathFilter {
    fn name(&self) -> &'static str {
        "PrefixPath"
    }
    async fn apply_request(&self, ctx: &mut FilterRequest<'_>) -> Result<()> {
        let prefix = self.prefix.trim_end_matches('/');
        let new_path = format!("{}{}", prefix, ctx.path);
        ctx.set_path(new_path);
        Ok(())
    }
}

/// 直接设置路径。
#[derive(Debug)]
pub struct SetPathFilter {
    pub path: String,
}

#[async_trait]
impl GatewayFilter for SetPathFilter {
    fn name(&self) -> &'static str {
        "SetPath"
    }
    async fn apply_request(&self, ctx: &mut FilterRequest<'_>) -> Result<()> {
        ctx.set_path(self.path.clone());
        Ok(())
    }
}

/// 正则重写路径。
#[derive(Debug)]
pub struct RewritePathFilter {
    regex: Regex,
    replacement: String,
}

impl RewritePathFilter {
    pub fn new(regex: &str, replacement: &str) -> Result<Self> {
        let regex = Regex::new(regex)
            .map_err(|e| GatewayError::Config(format!("invalid RewritePath regex: {e}")))?;
        Ok(Self {
            regex,
            replacement: replacement.to_string(),
        })
    }
}

#[async_trait]
impl GatewayFilter for RewritePathFilter {
    fn name(&self) -> &'static str {
        "RewritePath"
    }
    async fn apply_request(&self, ctx: &mut FilterRequest<'_>) -> Result<()> {
        if let Some(caps) = self.regex.captures(&ctx.path) {
            ctx.set_path(expand_replacement(&caps, &self.replacement));
        }
        Ok(())
    }
}

/// 添加请求头。
#[derive(Debug)]
pub struct AddRequestHeaderFilter {
    name: HeaderName,
    value: String,
}

#[async_trait]
impl GatewayFilter for AddRequestHeaderFilter {
    fn name(&self) -> &'static str {
        "AddRequestHeader"
    }
    async fn apply_request(&self, ctx: &mut FilterRequest<'_>) -> Result<()> {
        if let Ok(value) = HeaderValue::from_str(&self.value) {
            ctx.headers.append(self.name.clone(), value);
        }
        Ok(())
    }
}

/// 设置请求头（覆盖已有值）。
#[derive(Debug)]
pub struct SetRequestHeaderFilter {
    name: HeaderName,
    value: String,
}

#[async_trait]
impl GatewayFilter for SetRequestHeaderFilter {
    fn name(&self) -> &'static str {
        "SetRequestHeader"
    }
    async fn apply_request(&self, ctx: &mut FilterRequest<'_>) -> Result<()> {
        if let Ok(value) = HeaderValue::from_str(&self.value) {
            ctx.headers.insert(self.name.clone(), value);
        }
        Ok(())
    }
}

/// 删除请求头。
#[derive(Debug)]
pub struct RemoveRequestHeaderFilter {
    name: HeaderName,
}

#[async_trait]
impl GatewayFilter for RemoveRequestHeaderFilter {
    fn name(&self) -> &'static str {
        "RemoveRequestHeader"
    }
    async fn apply_request(&self, ctx: &mut FilterRequest<'_>) -> Result<()> {
        ctx.headers.remove(&self.name);
        Ok(())
    }
}

/// 添加响应头。
#[derive(Debug)]
pub struct AddResponseHeaderFilter {
    name: HeaderName,
    value: String,
}

impl GatewayFilter for AddResponseHeaderFilter {
    fn name(&self) -> &'static str {
        "AddResponseHeader"
    }
    fn apply_response(&self, ctx: &mut FilterResponse<'_>) -> Result<()> {
        if let Ok(value) = HeaderValue::from_str(&self.value) {
            ctx.headers.append(self.name.clone(), value);
        }
        Ok(())
    }
}

/// 设置响应头。
#[derive(Debug)]
pub struct SetResponseHeaderFilter {
    name: HeaderName,
    value: String,
}

impl GatewayFilter for SetResponseHeaderFilter {
    fn name(&self) -> &'static str {
        "SetResponseHeader"
    }
    fn apply_response(&self, ctx: &mut FilterResponse<'_>) -> Result<()> {
        if let Ok(value) = HeaderValue::from_str(&self.value) {
            ctx.headers.insert(self.name.clone(), value);
        }
        Ok(())
    }
}

/// 删除响应头。
#[derive(Debug)]
pub struct RemoveResponseHeaderFilter {
    name: HeaderName,
}

impl GatewayFilter for RemoveResponseHeaderFilter {
    fn name(&self) -> &'static str {
        "RemoveResponseHeader"
    }
    fn apply_response(&self, ctx: &mut FilterResponse<'_>) -> Result<()> {
        ctx.headers.remove(&self.name);
        Ok(())
    }
}

/// 添加查询参数。
#[derive(Debug)]
pub struct AddRequestParameterFilter {
    name: String,
    value: String,
}

#[async_trait]
impl GatewayFilter for AddRequestParameterFilter {
    fn name(&self) -> &'static str {
        "AddRequestParameter"
    }
    async fn apply_request(&self, ctx: &mut FilterRequest<'_>) -> Result<()> {
        let mut pairs: Vec<(String, String)> =
            url::form_urlencoded::parse(ctx.query.as_deref().unwrap_or_default().as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
        pairs.retain(|(k, _)| k != &self.name);
        pairs.push((self.name.clone(), self.value.clone()));
        let encoded: String = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .finish();
        ctx.query = if encoded.is_empty() {
            None
        } else {
            Some(encoded)
        };
        Ok(())
    }
}

/// 保留客户端原始 Host 头。
#[derive(Debug, Default)]
pub struct PreserveHostHeaderFilter;

#[async_trait]
impl GatewayFilter for PreserveHostHeaderFilter {
    fn name(&self) -> &'static str {
        "PreserveHostHeader"
    }
    async fn apply_request(&self, ctx: &mut FilterRequest<'_>) -> Result<()> {
        ctx.preserve_host = true;
        Ok(())
    }
}

/// 用请求头的值设置请求 URI。
#[derive(Debug)]
pub struct RequestHeaderToRequestUriFilter {
    name: HeaderName,
}

#[async_trait]
impl GatewayFilter for RequestHeaderToRequestUriFilter {
    fn name(&self) -> &'static str {
        "RequestHeaderToRequestUri"
    }
    async fn apply_request(&self, ctx: &mut FilterRequest<'_>) -> Result<()> {
        if let Some(value) = ctx.headers.get(&self.name).and_then(|v| v.to_str().ok()) {
            if let Ok(uri) = value.parse::<http::Uri>() {
                if let Some(path) = uri.path_and_query() {
                    ctx.path = path.path().to_string();
                    ctx.query = path.query().map(|q| q.to_string());
                }
            }
        }
        Ok(())
    }
}

/// 安全响应头。
#[derive(Debug, Default)]
pub struct SecureHeadersFilter;

impl GatewayFilter for SecureHeadersFilter {
    fn name(&self) -> &'static str {
        "SecureHeaders"
    }
    fn apply_response(&self, ctx: &mut FilterResponse<'_>) -> Result<()> {
        apply_secure_headers(ctx.headers);
        Ok(())
    }
}

/// 写入默认安全响应头（不覆盖已有值）。
pub fn apply_secure_headers(headers: &mut HeaderMap) {
    const DEFAULTS: &[(&str, &str)] = &[
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("x-xss-protection", "0"),
        ("content-security-policy", "default-src 'self'"),
    ];
    for (name, value) in DEFAULTS {
        if !headers.contains_key(*name) {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(name, value);
            }
        }
    }
}

fn expand_replacement(caps: &regex::Captures<'_>, template: &str) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if ch == '$' {
            match chars.peek() {
                Some((_, '{')) => {
                    chars.next();
                    let mut name = String::new();
                    let mut closed = false;
                    for (_, c) in chars.by_ref() {
                        if c == '}' {
                            closed = true;
                            break;
                        }
                        name.push(c);
                    }
                    if closed {
                        if let Some(m) = caps.name(&name) {
                            out.push_str(m.as_str());
                        }
                    }
                }
                Some((_, c)) if c.is_ascii_digit() => {
                    let idx = c.to_digit(10).unwrap_or(0) as usize;
                    chars.next();
                    if let Some(m) = caps.get(idx) {
                        out.push_str(m.as_str());
                    }
                }
                _ => out.push('$'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 过滤器注册表
// ---------------------------------------------------------------------------

/// 过滤器工厂：把配置参数转换为过滤器实例。
pub type FilterFactory =
    dyn Fn(&serde_yaml::Value) -> std::result::Result<Arc<dyn GatewayFilter>, String> + Send + Sync;

/// 过滤器注册表，支持注册自定义 Gateway Filter。
#[derive(Clone)]
pub struct FilterRegistry {
    factories: Arc<HashMap<String, Arc<FilterFactory>>>,
}

impl Default for FilterRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}

impl FilterRegistry {
    /// 构造包含全部内置过滤器的注册表。
    pub fn builtin() -> Self {
        let mut factories: HashMap<String, Arc<FilterFactory>> = HashMap::new();

        factories.insert(
            "stripprefix".into(),
            Arc::new(|args| {
                let parts = extract_usize(args, &["parts", "value", "n"])
                    .unwrap_or_else(|| extract_scalar_usize(args).unwrap_or(1));
                Ok(Arc::new(StripPrefixFilter { parts }) as Arc<dyn GatewayFilter>)
            }),
        );
        factories.insert(
            "prefixpath".into(),
            Arc::new(|args| {
                let prefix = extract_string(args, &["prefix", "value"])
                    .ok_or("PrefixPath requires a prefix")?;
                Ok(Arc::new(PrefixPathFilter { prefix }) as Arc<dyn GatewayFilter>)
            }),
        );
        factories.insert(
            "setpath".into(),
            Arc::new(|args| {
                let path =
                    extract_string(args, &["path", "value"]).ok_or("SetPath requires a path")?;
                Ok(Arc::new(SetPathFilter { path }) as Arc<dyn GatewayFilter>)
            }),
        );
        factories.insert(
            "rewritepath".into(),
            Arc::new(|args| {
                let (regex, replacement) =
                    extract_pair(args, &["regex", "pattern"], &["replacement", "value"])
                        .ok_or("RewritePath requires `regex,replacement`")?;
                let filter =
                    RewritePathFilter::new(&regex, &replacement).map_err(|e| e.to_string())?;
                Ok(Arc::new(filter) as Arc<dyn GatewayFilter>)
            }),
        );
        factories.insert(
            "addrequestheader".into(),
            Arc::new(|args| {
                let (name, value) = extract_pair(args, &["name"], &["value"])
                    .ok_or("AddRequestHeader requires `name,value`")?;
                let name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|e| format!("invalid header name: {e}"))?;
                Ok(Arc::new(AddRequestHeaderFilter { name, value }) as Arc<dyn GatewayFilter>)
            }),
        );
        factories.insert(
            "setrequestheader".into(),
            Arc::new(|args| {
                let (name, value) = extract_pair(args, &["name"], &["value"])
                    .ok_or("SetRequestHeader requires `name,value`")?;
                let name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|e| format!("invalid header name: {e}"))?;
                Ok(Arc::new(SetRequestHeaderFilter { name, value }) as Arc<dyn GatewayFilter>)
            }),
        );
        factories.insert(
            "removerequestheader".into(),
            Arc::new(|args| {
                let name = extract_string(args, &["name", "value"])
                    .ok_or("RemoveRequestHeader requires a header name")?;
                let name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|e| format!("invalid header name: {e}"))?;
                Ok(Arc::new(RemoveRequestHeaderFilter { name }) as Arc<dyn GatewayFilter>)
            }),
        );
        factories.insert(
            "addresponseheader".into(),
            Arc::new(|args| {
                let (name, value) = extract_pair(args, &["name"], &["value"])
                    .ok_or("AddResponseHeader requires `name,value`")?;
                let name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|e| format!("invalid header name: {e}"))?;
                Ok(Arc::new(AddResponseHeaderFilter { name, value }) as Arc<dyn GatewayFilter>)
            }),
        );
        factories.insert(
            "setresponseheader".into(),
            Arc::new(|args| {
                let (name, value) = extract_pair(args, &["name"], &["value"])
                    .ok_or("SetResponseHeader requires `name,value`")?;
                let name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|e| format!("invalid header name: {e}"))?;
                Ok(Arc::new(SetResponseHeaderFilter { name, value }) as Arc<dyn GatewayFilter>)
            }),
        );
        factories.insert(
            "removeresponseheader".into(),
            Arc::new(|args| {
                let name = extract_string(args, &["name", "value"])
                    .ok_or("RemoveResponseHeader requires a header name")?;
                let name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|e| format!("invalid header name: {e}"))?;
                Ok(Arc::new(RemoveResponseHeaderFilter { name }) as Arc<dyn GatewayFilter>)
            }),
        );
        factories.insert(
            "addrequestparameter".into(),
            Arc::new(|args| {
                let (name, value) = extract_pair(args, &["name"], &["value"])
                    .ok_or("AddRequestParameter requires `name,value`")?;
                Ok(Arc::new(AddRequestParameterFilter { name, value }) as Arc<dyn GatewayFilter>)
            }),
        );
        factories.insert(
            "preservehostheader".into(),
            Arc::new(|_| Ok(Arc::new(PreserveHostHeaderFilter) as Arc<dyn GatewayFilter>)),
        );
        factories.insert(
            "requestheadertorequesturi".into(),
            Arc::new(|args| {
                let name = extract_string(args, &["name", "header", "value"])
                    .ok_or("RequestHeaderToRequestUri requires a header name")?;
                let name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|e| format!("invalid header name: {e}"))?;
                Ok(Arc::new(RequestHeaderToRequestUriFilter { name }) as Arc<dyn GatewayFilter>)
            }),
        );
        factories.insert(
            "secureheaders".into(),
            Arc::new(|_| Ok(Arc::new(SecureHeadersFilter) as Arc<dyn GatewayFilter>)),
        );

        Self {
            factories: Arc::new(factories),
        }
    }

    /// 注册自定义过滤器工厂。
    pub fn with_filter<F>(mut self, name: &str, factory: F) -> Self
    where
        F: Fn(&serde_yaml::Value) -> std::result::Result<Arc<dyn GatewayFilter>, String>
            + Send
            + Sync
            + 'static,
    {
        let mut map = (*self.factories).clone();
        map.insert(name.to_ascii_lowercase(), Arc::new(factory));
        self.factories = Arc::new(map);
        self
    }

    /// 根据配置构造过滤器。
    pub fn create(&self, spec: &FilterSpec) -> std::result::Result<Arc<dyn GatewayFilter>, String> {
        let (name, args) = match spec {
            FilterSpec::Short(text) => parse_short_filter(text)?,
            FilterSpec::Full(obj) => (obj.name.clone(), obj.args.clone()),
        };
        let key = name.to_ascii_lowercase();
        let factory = self
            .factories
            .get(&key)
            .ok_or_else(|| format!("unknown filter `{name}`"))?;
        factory(&args)
    }
}

static FILTER_REGISTRY: Lazy<FilterRegistry> = Lazy::new(FilterRegistry::builtin);

/// 默认过滤器注册表。
pub fn default_registry() -> FilterRegistry {
    FILTER_REGISTRY.clone()
}

/// 解析 `Name=arg1,arg2` 形式的过滤器简写。
fn parse_short_filter(text: &str) -> std::result::Result<(String, serde_yaml::Value), String> {
    let trimmed = text.trim();
    let Some((name, rest)) = trimmed.split_once('=') else {
        return Ok((trimmed.to_string(), serde_yaml::Value::Null));
    };
    let name = name.trim().to_string();
    let rest = rest.trim();

    // RewritePath 的形式是 `regex,replacement`
    if name.eq_ignore_ascii_case("RewritePath") {
        let (regex, replacement) = rest
            .split_once(',')
            .ok_or("RewritePath requires `regex,replacement`")?;
        let mut map = serde_yaml::Mapping::new();
        map.insert(
            serde_yaml::Value::String("regex".into()),
            serde_yaml::Value::String(regex.trim().to_string()),
        );
        map.insert(
            serde_yaml::Value::String("replacement".into()),
            serde_yaml::Value::String(replacement.trim().to_string()),
        );
        return Ok((name, serde_yaml::Value::Mapping(map)));
    }

    if let Some((first, second)) = rest.split_once(',') {
        let mut map = serde_yaml::Mapping::new();
        map.insert(
            serde_yaml::Value::String("name".into()),
            serde_yaml::Value::String(first.trim().to_string()),
        );
        map.insert(
            serde_yaml::Value::String("value".into()),
            serde_yaml::Value::String(second.trim().to_string()),
        );
        Ok((name, serde_yaml::Value::Mapping(map)))
    } else {
        Ok((name, serde_yaml::Value::String(rest.to_string())))
    }
}

fn extract_string(args: &serde_yaml::Value, keys: &[&str]) -> Option<String> {
    match args {
        serde_yaml::Value::String(s) => {
            if s.is_empty() {
                None
            } else {
                Some(s.clone())
            }
        }
        serde_yaml::Value::Mapping(map) => keys.iter().find_map(|key| {
            map.get(serde_yaml::Value::String((*key).into()))
                .and_then(|v| match v {
                    serde_yaml::Value::String(s) => Some(s.clone()),
                    serde_yaml::Value::Number(n) => Some(n.to_string()),
                    serde_yaml::Value::Bool(b) => Some(b.to_string()),
                    _ => None,
                })
        }),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn extract_scalar_usize(args: &serde_yaml::Value) -> Option<usize> {
    match args {
        serde_yaml::Value::Number(n) => n.as_u64().map(|v| v as usize),
        serde_yaml::Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn extract_usize(args: &serde_yaml::Value, keys: &[&str]) -> Option<usize> {
    match args {
        serde_yaml::Value::Mapping(map) => keys.iter().find_map(|key| {
            map.get(serde_yaml::Value::String((*key).into()))
                .and_then(|v| match v {
                    serde_yaml::Value::Number(n) => n.as_u64().map(|v| v as usize),
                    serde_yaml::Value::String(s) => s.trim().parse().ok(),
                    _ => None,
                })
        }),
        _ => None,
    }
}

fn extract_pair(
    args: &serde_yaml::Value,
    name_keys: &[&str],
    value_keys: &[&str],
) -> Option<(String, String)> {
    match args {
        serde_yaml::Value::Mapping(map) => {
            let name = extract_string(args, name_keys)?;
            let value = value_keys.iter().find_map(|key| {
                map.get(serde_yaml::Value::String((*key).into()))
                    .and_then(|v| match v {
                        serde_yaml::Value::String(s) => Some(s.clone()),
                        serde_yaml::Value::Number(n) => Some(n.to_string()),
                        serde_yaml::Value::Bool(b) => Some(b.to_string()),
                        _ => None,
                    })
            })?;
            Some((name, value))
        }
        serde_yaml::Value::Sequence(seq) if seq.len() >= 2 => {
            Some((seq[0].as_str()?.to_string(), seq[1].as_str()?.to_string()))
        }
        _ => None,
    }
}

/// 编译路由过滤器列表并排序。
pub fn compile_filters(
    registry: &FilterRegistry,
    specs: &[FilterSpec],
) -> std::result::Result<Vec<Arc<dyn GatewayFilter>>, String> {
    let mut filters = Vec::with_capacity(specs.len());
    for spec in specs {
        filters.push(registry.create(spec)?);
    }
    filters.sort_by_key(|f| f.order());
    Ok(filters)
}

/// 从 FilterObject 构造（供管理 API 使用）。
pub fn create_from_object(
    registry: &FilterRegistry,
    obj: &FilterObject,
) -> std::result::Result<Arc<dyn GatewayFilter>, String> {
    registry.create(&FilterSpec::Full(obj.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_prefix_rewrites_path() {
        let filter = StripPrefixFilter { parts: 2 };
        let mut headers = HeaderMap::new();
        let method = Method::GET;
        let metadata = HashMap::new();
        let mut ctx = FilterRequest {
            method: &method,
            path: "/api/users/1".to_string(),
            query: None,
            headers: &mut headers,
            identity: None,
            metadata: &metadata,
            preserve_host: false,
        };
        futures::executor::block_on(filter.apply_request(&mut ctx)).unwrap();
        assert_eq!(ctx.path, "/1");
    }

    #[test]
    fn rewrite_path_supports_named_groups() {
        let filter = RewritePathFilter::new("/api/(?<segment>.*)", "/${segment}").unwrap();
        let mut headers = HeaderMap::new();
        let method = Method::GET;
        let metadata = HashMap::new();
        let mut ctx = FilterRequest {
            method: &method,
            path: "/api/users/1".to_string(),
            query: None,
            headers: &mut headers,
            identity: None,
            metadata: &metadata,
            preserve_host: false,
        };
        futures::executor::block_on(filter.apply_request(&mut ctx)).unwrap();
        assert_eq!(ctx.path, "/users/1");
    }

    #[test]
    fn shorthand_parsing() {
        let registry = default_registry();
        let spec = FilterSpec::Short("StripPrefix=2".to_string());
        let filter = registry.create(&spec).unwrap();
        assert_eq!(filter.name(), "StripPrefix");

        let spec = FilterSpec::Short("AddRequestHeader=X-Gateway, rust-gateway".to_string());
        let filter = registry.create(&spec).unwrap();
        assert_eq!(filter.name(), "AddRequestHeader");

        assert!(registry
            .create(&FilterSpec::Short("UnknownFilter=1".to_string()))
            .is_err());
    }

    #[test]
    fn add_request_parameter_merges_query() {
        let filter = AddRequestParameterFilter {
            name: "debug".into(),
            value: "1".into(),
        };
        let mut headers = HeaderMap::new();
        let method = Method::GET;
        let metadata = HashMap::new();
        let mut ctx = FilterRequest {
            method: &method,
            path: "/".into(),
            query: Some("a=b".into()),
            headers: &mut headers,
            identity: None,
            metadata: &metadata,
            preserve_host: false,
        };
        futures::executor::block_on(filter.apply_request(&mut ctx)).unwrap();
        let query = ctx.query.unwrap();
        assert!(query.contains("a=b"));
        assert!(query.contains("debug=1"));
    }
}
