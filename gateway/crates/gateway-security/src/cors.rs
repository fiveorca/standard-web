//! CORS 插件 —— 请求方向处理预检（OPTIONS 204），响应方向追加 CORS 头。
//!
//! # 设计
//!
//! CORS 的两条语义（预检短路 + 响应头追加）是同一策略的两面，
//! 但 `Plugin::phase()` 只能返回一个阶段值，因此在 `from_configs` 中
//! 一次性编译好策略表，再拆出**两个**插件实例（Request 阶段 / Response 阶段
//! 各一个），由调用方（RuntimeState）分别注册到 `PluginRegistry`。
//!
//! ```text
//! RequestPostRoute（priority = 5）
//!   ├── OPTIONS + Origin + ACRM → 预检校验 → 成功 ShortCircuit(204) / 失败 ShortCircuit(403)
//!   └── 其他 → Continue
//!
//! ResponsePreClient（priority = 5）
//!   ├── route 无 cors_policy_id 或请求无 Origin → Continue
//!   └── 命中策略 → 追加 ACAO / ACAC / ACEH / Vary: Origin
//! ```
//!
//! # fail closed 约定
//! - Route 没有 `cors_policy_id` → 不生效（Continue）
//! - Route 引用了不存在的策略 → `Err`，Runtime 映射为 500，**不放行**
//! - 预检不通过 → `ShortCircuit(403/405)`，不放行
//! - 允许任意 Origin 同时要求凭据 → 编译期报错，阻止启动

use std::collections::HashMap;
use std::sync::Arc;

use gateway_core::CorsPolicyConfig;
use gateway_plugin::{
    Plugin, PluginContext, PluginDecision, PluginError, PluginPhase, PluginResponse,
};
use http::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE,
    ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, ORIGIN, VARY,
};
use http::{HeaderValue, Method, StatusCode};

/// 请求方向 CORS 插件名。
pub const CORS_REQUEST_PLUGIN_NAME: &str = "cors_request";
/// 响应方向 CORS 插件名。
pub const CORS_RESPONSE_PLUGIN_NAME: &str = "cors_response";

// ---------------------------------------------------------------------------
// 已编译策略
// ---------------------------------------------------------------------------

/// 单条已编译 CORS 策略（一次编译，两阶段共享）。
#[derive(Debug)]
pub struct CompiledCorsPolicy {
    /// 原始策略 ID
    pub id: String,
    /// 允许的 origins（已排序、去重）；`*` 由 `allow_any_origin` 标记
    pub allow_origins: Vec<String>,
    /// 是否允许任意 Origin（策略中含 `*`）
    pub allow_any_origin: bool,
    /// 允许的 HTTP methods（已排序、去重）
    pub allow_methods: Vec<String>,
    /// 允许的请求头（已排序、去重）
    pub allow_headers: Vec<String>,
    /// 是否允许任意请求头（策略中含 `*`）
    pub allow_any_headers: bool,
    /// 允许暴露的响应头（已排序、去重）
    pub expose_headers: Vec<String>,
    /// 是否允许携带凭据
    pub allow_credentials: bool,
    /// 预检结果浏览器缓存时长（秒）
    pub max_age_secs: u64,
}

impl CompiledCorsPolicy {
    /// 从原始 YAML 配置编译；不校验 enabled 或空 id（由上层过滤）。
    pub fn compile(cfg: &CorsPolicyConfig) -> Self {
        let mut allow_origins = cfg.allow_origins.clone();
        allow_origins.sort();
        allow_origins.dedup();
        let allow_any_origin = allow_origins.iter().any(|o| o == "*");

        let mut allow_methods = cfg.allow_methods.clone();
        allow_methods.sort();
        allow_methods.dedup();

        let mut allow_headers = cfg.allow_headers.clone();
        allow_headers.sort();
        allow_headers.dedup();
        let allow_any_headers = allow_headers.iter().any(|h| h == "*");
        let mut expose_headers = cfg.expose_headers.clone();
        expose_headers.sort();
        expose_headers.dedup();

        Self {
            id: cfg.id.clone(),
            allow_origins,
            allow_any_origin,
            allow_methods,
            allow_headers,
            allow_any_headers,
            expose_headers,
            allow_credentials: cfg.allow_credentials,
            max_age_secs: cfg.max_age_secs,
        }
    }

    /// Origin 是否允许。
    pub fn origin_allowed(&self, origin: &str) -> bool {
        self.allow_any_origin || self.allow_origins.iter().any(|o| o == origin)
    }

    /// Method 是否允许（大小写不敏感）。
    pub fn method_allowed(&self, method: &str) -> bool {
        let method = method.to_ascii_uppercase();
        // clippy::manual_contains：Vec<String> 已排序，binary search 比 iter any 更快
        self.allow_methods.binary_search(&method).is_ok()
    }

    /// 请求头集合是否都被 allow_headers 覆盖（大小写不敏感）。
    pub fn headers_allowed(&self, request_headers: &[&str]) -> bool {
        if self.allow_any_headers {
            return true;
        }
        request_headers.iter().all(|rh| {
            let rh = rh.to_ascii_lowercase();
            self.allow_headers
                .iter()
                .any(|ah| ah.to_ascii_lowercase() == rh)
        })
    }

    /// 为**预检响应**构造全部 CORS 头（含 Max-Age / Methods / Headers / Vary: Origin）。
    pub fn build_preflight_headers(
        &self,
        origin: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, PluginError> {
        let mut out: Vec<(String, Vec<u8>)> = Vec::new();
        let acao = if self.allow_any_origin && !self.allow_credentials {
            "*".to_string()
        } else {
            origin.to_string()
        };
        out.push((
            ACCESS_CONTROL_ALLOW_ORIGIN.as_str().to_string(),
            acao.into_bytes(),
        ));
        if self.allow_credentials {
            out.push((
                ACCESS_CONTROL_ALLOW_CREDENTIALS.as_str().to_string(),
                b"true".to_vec(),
            ));
        }
        let joined = self.allow_methods.join(", ");
        out.push((
            ACCESS_CONTROL_ALLOW_METHODS.as_str().to_string(),
            joined.into_bytes(),
        ));
        let ah = if self.allow_any_headers {
            "*".to_string()
        } else {
            self.allow_headers.join(", ")
        };
        out.push((
            ACCESS_CONTROL_ALLOW_HEADERS.as_str().to_string(),
            ah.into_bytes(),
        ));
        out.push((
            ACCESS_CONTROL_MAX_AGE.as_str().to_string(),
            self.max_age_secs.to_string().into_bytes(),
        ));
        out.push((VARY.as_str().to_string(), b"Origin".to_vec()));
        Ok(out)
    }

    /// 为**普通响应**构造 CORS 头（不含 Max-Age / Methods / Headers）。
    pub fn build_simple_headers(
        &self,
        origin: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, PluginError> {
        let mut out: Vec<(String, Vec<u8>)> = Vec::new();
        let acao = if self.allow_any_origin && !self.allow_credentials {
            "*".to_string()
        } else {
            origin.to_string()
        };
        out.push((
            ACCESS_CONTROL_ALLOW_ORIGIN.as_str().to_string(),
            acao.into_bytes(),
        ));
        if self.allow_credentials {
            out.push((
                ACCESS_CONTROL_ALLOW_CREDENTIALS.as_str().to_string(),
                b"true".to_vec(),
            ));
        }
        if !self.expose_headers.is_empty() {
            out.push((
                ACCESS_CONTROL_EXPOSE_HEADERS.as_str().to_string(),
                self.expose_headers.join(", ").into_bytes(),
            ));
        }
        // 预检阶段已经写过 Vary: Origin，但 Runtime 会合并所有插件的头，
        // 所以这里再写一次是安全的（HeaderMap.insert 语义）
        out.push((VARY.as_str().to_string(), b"Origin".to_vec()));
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// 两阶段构造器
// ---------------------------------------------------------------------------

/// 从 YAML 策略集合编译出两个插件（请求 / 响应各一个，共享策略表）。
///
/// 返回值 `(request_plugin, response_plugin)` 由调用方分别注册到注册表。
pub fn build_cors_plugins(
    configs: &[CorsPolicyConfig],
) -> Result<(CorsRequestPlugin, CorsResponsePlugin), PluginError> {
    let mut map = HashMap::new();
    for cfg in configs {
        if !cfg.enabled || cfg.id.is_empty() {
            continue;
        }
        // 互斥约束：浏览器规范禁止 allow_credentials=true + allow_origins=['*']
        if cfg.allow_credentials && cfg.allow_origins.iter().any(|o| o == "*") {
            return Err(PluginError::Other(format!(
                "CORS policy '{}': allow_credentials=true 与 allow_origins=['*'] 互斥",
                cfg.id
            )));
        }
        map.insert(cfg.id.clone(), CompiledCorsPolicy::compile(cfg));
    }
    let policies = Arc::new(map);
    Ok((
        CorsRequestPlugin {
            policies: policies.clone(),
        },
        CorsResponsePlugin { policies },
    ))
}

// ---------------------------------------------------------------------------
// 请求方向插件（预检）
// ---------------------------------------------------------------------------

/// 请求方向 CORS 插件：只处理 OPTIONS 预检。
#[derive(Debug, Clone)]
pub struct CorsRequestPlugin {
    policies: Arc<HashMap<String, CompiledCorsPolicy>>,
}

#[async_trait::async_trait]
impl Plugin for CorsRequestPlugin {
    fn name(&self) -> &'static str {
        CORS_REQUEST_PLUGIN_NAME
    }
    fn phase(&self) -> PluginPhase {
        PluginPhase::RequestPostRoute
    }
    fn priority(&self) -> i32 {
        5
    }

    async fn execute(&self, ctx: &mut PluginContext<'_>) -> Result<PluginDecision, PluginError> {
        let route = match ctx.route.as_ref() {
            Some(r) => r,
            None => {
                return Err(PluginError::Other(
                    "cors_request: 没有 route（装配错误）".into(),
                ))
            },
        };
        let policy_id = match &route.cors_policy_id {
            Some(id) => id,
            None => return Ok(PluginDecision::Continue),
        };
        let policy = self.policies.get(policy_id).ok_or_else(|| {
            PluginError::Other(format!(
                "cors_request: route '{}' 引用不存在的策略 '{}'",
                route.id, policy_id
            ))
        })?;

        // 只处理 OPTIONS 预检（parts.method 是 Method，不是 &Method）
        if ctx.parts.method != Method::OPTIONS {
            return Ok(PluginDecision::Continue);
        }
        // 必须同时有 Origin + Access-Control-Request-Method 才是预检
        let origin = match ctx.header(&ORIGIN) {
            Some(v) => v.to_str().unwrap_or("").to_string(),
            None => return Ok(PluginDecision::Continue),
        };
        let req_method = match ctx.header(&ACCESS_CONTROL_REQUEST_METHOD) {
            Some(v) => v.to_str().unwrap_or("").to_string(),
            None => return Ok(PluginDecision::Continue),
        };

        // Origin 不允许 → 403
        if !policy.origin_allowed(&origin) {
            return Ok(PluginDecision::ShortCircuit(PluginResponse::from_error(
                StatusCode::FORBIDDEN,
                "CORS_ORIGIN_NOT_ALLOWED",
                "origin not in allow_origins",
                Some(ctx.request_id()),
            )));
        }
        // Method 不允许 → 405
        if !policy.method_allowed(&req_method) {
            return Ok(PluginDecision::ShortCircuit(PluginResponse::from_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "CORS_METHOD_NOT_ALLOWED",
                "request method not in allow_methods",
                Some(ctx.request_id()),
            )));
        }
        // Request-Headers 不允许 → 403
        if let Some(rh) = ctx.header(&ACCESS_CONTROL_REQUEST_HEADERS) {
            let split: Vec<&str> = rh
                .to_str()
                .unwrap_or("")
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if !policy.headers_allowed(&split) {
                return Ok(PluginDecision::ShortCircuit(PluginResponse::from_error(
                    StatusCode::FORBIDDEN,
                    "CORS_HEADERS_NOT_ALLOWED",
                    "request headers not in allow_headers",
                    Some(ctx.request_id()),
                )));
            }
        }

        // 全部通过 → 204 + 完整 CORS 头
        let headers = policy.build_preflight_headers(&origin)?;
        let mut resp = PluginResponse::empty(StatusCode::NO_CONTENT);
        for (name, value) in &headers {
            if let (Ok(name), Ok(value)) = (
                http::header::HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_bytes(value),
            ) {
                resp.headers.insert(name, value);
            }
        }
        Ok(PluginDecision::ShortCircuit(resp))
    }
}

// ---------------------------------------------------------------------------
// 响应方向插件（追加头）
// ---------------------------------------------------------------------------

/// 响应方向 CORS 插件：给正常响应追加 ACAO / ACAC / ACEH / Vary: Origin。
#[derive(Debug, Clone)]
pub struct CorsResponsePlugin {
    policies: Arc<HashMap<String, CompiledCorsPolicy>>,
}

#[async_trait::async_trait]
impl Plugin for CorsResponsePlugin {
    fn name(&self) -> &'static str {
        CORS_RESPONSE_PLUGIN_NAME
    }
    fn phase(&self) -> PluginPhase {
        PluginPhase::ResponsePreClient
    }
    fn priority(&self) -> i32 {
        5
    }

    async fn execute(&self, ctx: &mut PluginContext<'_>) -> Result<PluginDecision, PluginError> {
        let route = match ctx.route.as_ref() {
            Some(r) => r,
            None => {
                return Err(PluginError::Other(
                    "cors_response: 没有 route（装配错误）".into(),
                ))
            },
        };
        let policy_id = match &route.cors_policy_id {
            Some(id) => id,
            None => return Ok(PluginDecision::Continue),
        };
        let policy = self.policies.get(policy_id).ok_or_else(|| {
            PluginError::Other(format!(
                "cors_response: route '{}' 引用不存在的策略 '{}'",
                route.id, policy_id
            ))
        })?;

        // 只有请求带 Origin 才写 CORS 头（同源请求浏览器不带 Origin）
        let origin = match ctx.header(&ORIGIN) {
            Some(v) => v.to_str().unwrap_or("").to_string(),
            None => return Ok(PluginDecision::Continue),
        };
        if !policy.origin_allowed(&origin) {
            return Ok(PluginDecision::Continue);
        }

        // 追加头到 ResponseParts（Runtime 执行完所有插件后统一写回真实响应）
        let Some(resp_parts) = ctx.response_mut() else {
            // 不是响应阶段装配错误 → 当作 Continue 处理（fail open，不影响主链路）
            tracing::warn!("cors_response: PluginContext.response 为 None（装配错误，跳过）");
            return Ok(PluginDecision::Continue);
        };
        let headers = policy.build_simple_headers(&origin)?;
        for (name, value) in &headers {
            if let (Ok(name), Ok(value)) = (
                http::header::HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_bytes(value),
            ) {
                // 允许同一个 HeaderName 出现多次（Vary: Origin 会被合并）
                resp_parts.headers.append(name, value);
            }
        }
        Ok(PluginDecision::Continue)
    }
}
