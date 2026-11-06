//! WAF（Web Application Firewall）插件（Phase 7）。
//!
//! # 规则模型
//!
//! 内置规则覆盖四类高置信度攻击特征（OWASP CRS 的核心子集）：
//!
//! | 类别 | 示例特征 |
//! |---|---|
//! | SQL 注入 | `union select`、`information_schema`、`sleep(` |
//! | XSS | `<script`、`javascript:`、`onerror=` |
//! | 路径遍历 | `../`、`%2e%2e%2f`、`/etc/passwd` |
//! | 命令注入 | `$(...`、`` ` ``、`;cat `、`|whoami` |
//!
//! 输入先做百分号解码（最多两层），避免 `%3Cscript%3E` 绕过。
//!
//! # 检查范围
//!
//! - `path` / `query` / `headers`：插件阶段直接可读
//! - `body`：需要 Runtime 预读请求体（`PluginContext::body`），
//!   超过策略 `max_body_bytes` 时跳过 body 检查（记录日志）
//!
//! # 动作
//!
//! - `Block`：短路返回 403（`GATEWAY_WAF_BLOCKED`）
//! - `Detect`：只记录警告日志，请求继续

use std::collections::HashMap;
use std::sync::Arc;

use gateway_core::{WafAction, WafPolicyConfig, WafSensitivity, WafTarget};
use gateway_plugin::{
    Plugin, PluginContext, PluginDecision, PluginError, PluginPhase, PluginResponse,
};
use http::StatusCode;

/// 插件名（注册表键）。
pub const WAF_PLUGIN_NAME: &str = "waf";

/// 安全插件优先级：认证（10）之后、请求转换（25）之前。
const WAF_PRIORITY: i32 = 15;

/// 编译后的 WAF 策略集合。
#[derive(Debug, Clone, Default)]
pub struct CompiledWafPolicies {
    /// 策略 ID → 策略配置
    policies: HashMap<String, WafPolicyConfig>,
}

impl CompiledWafPolicies {
    /// 编译配置集合。
    ///
    /// 返回 `Err(String)` 表示策略非法（例如 limit 为 0、目标为空）。
    pub fn compile(configs: &[WafPolicyConfig]) -> Result<Self, String> {
        let mut policies = HashMap::new();
        for config in configs.iter().filter(|c| c.enabled) {
            if config.id.is_empty() {
                return Err("waf policy id must not be empty".to_string());
            }
            if policies.contains_key(&config.id) {
                return Err(format!("duplicate waf policy id '{}'", config.id));
            }
            if config.targets.is_empty() {
                return Err(format!("waf policy '{}': targets must not be empty", config.id));
            }
            if config.max_body_bytes == 0 {
                return Err(format!(
                    "waf policy '{}': max_body_bytes must be greater than 0",
                    config.id
                ));
            }
            policies.insert(config.id.clone(), config.clone());
        }
        Ok(Self { policies })
    }

    /// 按 ID 取策略。
    pub fn get(&self, id: &str) -> Option<&WafPolicyConfig> {
        self.policies.get(id)
    }

    /// 策略数量。
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
}

/// WAF 插件。
#[derive(Debug, Clone)]
pub struct WafPlugin {
    /// 策略表（启动期编译，只读）
    policies: Arc<CompiledWafPolicies>,
}

impl WafPlugin {
    /// 用已编译策略构造插件。
    pub fn new(policies: Arc<CompiledWafPolicies>) -> Self {
        Self { policies }
    }

    /// 从配置编译插件。
    pub fn from_configs(configs: &[WafPolicyConfig]) -> Result<Self, PluginError> {
        let policies = CompiledWafPolicies::compile(configs).map_err(|message| {
            PluginError::ConfigInvalid {
                plugin: WAF_PLUGIN_NAME.to_string(),
                message,
            }
        })?;
        Ok(Self::new(Arc::new(policies)))
    }
}

#[async_trait::async_trait]
impl Plugin for WafPlugin {
    fn name(&self) -> &'static str {
        WAF_PLUGIN_NAME
    }

    fn phase(&self) -> PluginPhase {
        PluginPhase::RequestPostRoute
    }

    fn priority(&self) -> i32 {
        WAF_PRIORITY
    }

    async fn execute(&self, ctx: &mut PluginContext<'_>) -> Result<PluginDecision, PluginError> {
        // 未配置 WAF 的路由直接放行
        let Some(route) = ctx.route.as_ref() else {
            return Ok(PluginDecision::Continue);
        };
        let Some(policy_id) = route.waf_policy_id.as_ref() else {
            return Ok(PluginDecision::Continue);
        };
        let Some(policy) = self.policies.get(policy_id) else {
            // 引用完整性在配置校验阶段已保证；这里是热更新边界的兜底
            tracing::warn!(
                target: "waf",
                request_id = ctx.request_id(),
                policy = %policy_id,
                "waf policy referenced by route not found"
            );
            return Ok(PluginDecision::Continue);
        };

        let mut findings: Vec<(&'static str, String)> = Vec::new();

        if policy.targets.contains(&WafTarget::Path) {
            if let Some(hit) = inspect(policy.sensitivity, ctx.parts.uri.path()) {
                findings.push((hit, "path".to_string()));
            }
        }
        if policy.targets.contains(&WafTarget::Query) {
            if let Some(query) = ctx.parts.uri.query() {
                if let Some(hit) = inspect(policy.sensitivity, query) {
                    findings.push((hit, "query".to_string()));
                }
            }
        }
        if policy.targets.contains(&WafTarget::Headers) {
            for (name, value) in ctx.parts.headers.iter() {
                // Host / Date 等基础头不参与特征匹配，减少误报
                if matches!(name.as_str(), "host" | "date" | "content-length" | "content-type") {
                    continue;
                }
                let Ok(text) = value.to_str() else {
                    continue;
                };
                if let Some(hit) = inspect(policy.sensitivity, text) {
                    findings.push((hit, format!("header:{name}")));
                    // 每个请求只报告第一处命中即可（避免日志爆炸）
                    break;
                }
            }
        }
        if policy.targets.contains(&WafTarget::Body) {
            match ctx.body {
                Some(body) => {
                    // 超限时不检查 body（避免大包拖慢请求），但仍记录
                    if body.len() as u64 <= policy.max_body_bytes {
                        if let Ok(text) = std::str::from_utf8(body) {
                            if let Some(hit) = inspect(policy.sensitivity, text) {
                                findings.push((hit, "body".to_string()));
                            }
                        }
                    } else {
                        tracing::debug!(
                            target: "waf",
                            request_id = ctx.request_id(),
                            body_bytes = body.len(),
                            limit = policy.max_body_bytes,
                            "request body exceeds waf inspection limit, skipped"
                        );
                    }
                },
                None => {
                    tracing::debug!(
                        target: "waf",
                        request_id = ctx.request_id(),
                        "waf body inspection requested but body not buffered"
                    );
                },
            }
        }

        if findings.is_empty() {
            return Ok(PluginDecision::Continue);
        }

        // 记录命中（无论 Block 还是 Detect）
        for (rule, location) in &findings {
            tracing::warn!(
                target: "waf",
                request_id = ctx.request_id(),
                policy = %policy.id,
                rule = %rule,
                location = %location,
                "waf rule matched"
            );
        }

        if policy.action == WafAction::Detect {
            return Ok(PluginDecision::Continue);
        }

        // Block：写错误码便于审计与指标聚合，短路 403
        ctx.ctx.error_code = Some("GATEWAY_WAF_BLOCKED".to_string());
        ctx.ctx.error_message = Some(format!(
            "request blocked by waf rule '{}'",
            findings.first().map(|(rule, _)| *rule).unwrap_or("unknown")
        ));
        Ok(PluginDecision::ShortCircuit(PluginResponse::from_error(
            StatusCode::FORBIDDEN,
            "GATEWAY_WAF_BLOCKED",
            "request blocked by web application firewall",
            Some(ctx.request_id()),
        )))
    }
}

/// 百分号解码（最多两层，防止双重编码绕过）。
fn percent_decode(input: &str) -> String {
    fn decode_once(input: &str) -> String {
        let bytes = input.as_bytes();
        let mut out = String::with_capacity(input.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let hex = &input[i + 1..i + 3];
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    if byte.is_ascii() {
                        out.push(byte as char);
                    } else {
                        out.push('%');
                    }
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i] as char);
            i += 1;
        }
        out
    }

    let once = decode_once(input);
    decode_once(&once)
}

/// 检查一段文本，返回命中的规则标识。
///
/// 返回 `None` 表示未命中。规则按灵敏度分层：
/// - Low：只保留高置信度特征
/// - Medium：加入常见组合特征
/// - High：加入高误报特征（如单独的 `--`、`;`）
fn inspect(sensitivity: WafSensitivity, input: &str) -> Option<&'static str> {
    let decoded = percent_decode(input);
    let lower = decoded.to_ascii_lowercase();

    // ---- 高置信度（Low 及以上）----
    const HIGH_CONFIDENCE: &[(&str, &str)] = &[
        ("sqli", "union select"),
        ("sqli", "information_schema"),
        ("sqli", "sleep("),
        ("sqli", "benchmark("),
        ("sqli", "xp_cmdshell"),
        ("xss", "<script"),
        ("xss", "document.cookie"),
        ("xss", "<iframe"),
        ("traversal", "../"),
        ("traversal", "..\\"),
        ("traversal", "/etc/passwd"),
        ("traversal", "/proc/self/"),
        ("cmd", "$("),
        ("cmd", "`"),
    ];

    // ---- 中置信度（Medium 及以上）----
    const MEDIUM_CONFIDENCE: &[(&str, &str)] = &[
        ("sqli", "' or "),
        ("sqli", "\" or "),
        ("sqli", "';"),
        ("xss", "javascript:"),
        ("xss", "onerror="),
        ("xss", "onload="),
        ("cmd", "|whoami"),
        ("cmd", ";cat "),
        ("cmd", "&&"),
    ];

    // ---- 低置信度（仅 High）----
    const LOW_CONFIDENCE: &[(&str, &str)] = &[("sqli", "--"), ("cmd", "|"), ("cmd", ";")];

    let matches = |rules: &'static [(&'static str, &'static str)]| -> Option<&'static str> {
        rules.iter().find(|(_, pattern)| lower.contains(pattern)).map(|(rule, _)| *rule)
    };

    if let Some(rule) = matches(HIGH_CONFIDENCE) {
        return Some(rule);
    }
    if sensitivity != WafSensitivity::Low {
        if let Some(rule) = matches(MEDIUM_CONFIDENCE) {
            return Some(rule);
        }
    }
    if sensitivity == WafSensitivity::High {
        if let Some(rule) = matches(LOW_CONFIDENCE) {
            return Some(rule);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sqli() {
        assert!(inspect(WafSensitivity::Low, "id=1 UNION SELECT 1").is_some());
        assert!(inspect(WafSensitivity::Low, "q=information_schema.tables").is_some());
    }

    #[test]
    fn detects_xss() {
        assert!(inspect(WafSensitivity::Low, "<script>alert(1)</script>").is_some());
        // 百分号编码绕过
        assert!(inspect(WafSensitivity::Low, "%3Cscript%3E").is_some());
    }

    #[test]
    fn detects_traversal() {
        assert!(inspect(WafSensitivity::Low, "../../etc/passwd").is_some());
        assert!(inspect(WafSensitivity::Low, "%2e%2e%2fetc%2fpasswd").is_some());
    }

    #[test]
    fn low_sensitivity_avoids_false_positive() {
        // 单独的 "--" 只在 High 灵敏度命中
        assert!(inspect(WafSensitivity::Low, "hello -- world").is_none());
        assert!(inspect(WafSensitivity::High, "hello -- world").is_some());
    }

    #[test]
    fn benign_input_passes() {
        assert!(inspect(WafSensitivity::High, "hello world").is_none());
    }
}
