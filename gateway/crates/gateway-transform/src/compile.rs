//! Header 转换策略编译。
//!
//! 把 YAML 反序列化得到的 `TransformPolicyConfig` 编译为执行时可用的形态：
//!   - Header 名预解析为 `HeaderName`（启动期做一次，请求路径只做匹配）
//!   - `add_headers` / `set_headers` 的值保留原始模板字符串（运行期做占位符替换）
//!
//! # 与插件的关系
//! 与 gateway-security / gateway-traffic 的编译策略同构：
//!   ```text
//!   TransformPolicyConfig（YAML，纯数据）
//!           │ compile（启动期，一次性）
//!           ▼
//!   CompiledTransformPolicy（预解析 HeaderName）
//!           │ execute（请求/响应阶段执行）
//!           ▼
//!   HeaderMap 原地改写
//!   ```

use std::collections::HashMap;

use gateway_core::{HeaderEntryConfig, TransformPolicyConfig};
use http::header::HeaderName;

use crate::placeholder::{render, sanitize_header_value, PlaceholderEnv};

/// 单个 Header 转换操作。
///
/// 与 gateway-config 的 `HeaderEntryConfig` 一一对应，但 HeaderName
/// 已预解析（启动期做一次，请求路径零解析开销）。
#[derive(Debug, Clone)]
pub struct HeaderAction {
    /// Header 名称（已预解析为规范化类型）
    pub name: HeaderName,
    /// 值模板（运行期做占位符替换后写入）
    pub value: String,
}

/// 已编译的 Header 转换策略。
#[derive(Debug, Clone)]
pub struct CompiledTransformPolicy {
    /// 策略 ID（与 RouteConfig 的 transform_id 引用对应）
    pub id: String,
    /// 人类可读名称
    pub name: Option<String>,
    /// 是否启用
    pub enabled: bool,
    /// 删除的 Header 名列表（已预解析）
    pub remove: Vec<HeaderName>,
    /// 覆盖写入的 Header（值模板，运行期替换后写入）
    pub set: Vec<HeaderAction>,
    /// 追加写入的 Header（值模板，运行期替换后追加）
    pub add: Vec<HeaderAction>,
}

/// 全部转换策略的编译结果。
#[derive(Debug, Default)]
pub struct CompiledTransformPolicies {
    by_id: HashMap<String, CompiledTransformPolicy>,
}

impl CompiledTransformPolicies {
    /// 编译全部转换策略。
    ///
    /// 参数：
    /// - `configs`：`policies.request_transform` / `policies.response_transform`
    ///   段的原始配置（Phase 2 下两者共享同一类型，分开编译为两个集合）
    ///
    /// 返回 `Err` 时**整个集合拒绝加载**：避免"部分策略头名解析失败、
    /// 其余生效"的半故障状态。
    pub fn compile(configs: &[TransformPolicyConfig]) -> Result<Self, String> {
        let mut by_id = HashMap::with_capacity(configs.len());

        for (idx, config) in configs.iter().enumerate() {
            if config.id.is_empty() {
                return Err(format!("transform[{idx}].id must not be empty"));
            }
            if by_id.contains_key(&config.id) {
                return Err(format!(
                    "duplicate transform policy id '{}'",
                    config.id
                ));
            }

            let compiled = CompiledTransformPolicy::compile(config)
                .map_err(|reason| {
                    format!("transform[{idx}] ('{}'): {reason}", config.id)
                })?;
            by_id.insert(config.id.clone(), compiled);
        }

        Ok(Self { by_id })
    }

    /// 按 ID 查找已编译策略。
    pub fn get(&self, id: &str) -> Option<&CompiledTransformPolicy> {
        self.by_id.get(id)
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

impl CompiledTransformPolicy {
    /// 编译单条转换策略。
    pub fn compile(config: &TransformPolicyConfig) -> Result<Self, String> {
        // 1) 删除的 Header 名：逐个预解析
        let mut remove = Vec::with_capacity(config.remove_headers.len());
        for name in &config.remove_headers {
            // HeaderName 要求合法 ASCII、无 CR/LF/NUL；配置 validator 已校验过，
            // 这里再做一次属于防御式编程
            let parsed = HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| format!("remove_header '{name}': {e}"))?;
            remove.push(parsed);
        }

        // 2) set / add Header：预解析 HeaderName，值保留模板字符串
        let set = compile_actions(&config.set_headers, "set")?;
        let add = compile_actions(&config.add_headers, "add")?;

        Ok(Self {
            id: config.id.clone(),
            name: config.name.clone(),
            enabled: config.enabled,
            remove,
            set,
            add,
        })
    }

    /// 执行 Header 转换，改写 HeaderMap。
    ///
    /// 参数：
    /// - `headers`：要改写的 HeaderMap（请求方向是 `parts.headers`，响应方向是 `response.headers`）
    /// - `env`：占位符替换所需的请求环境快照
    ///
    /// 返回 `Err` 当某个 Header 值替换后仍非法（CR/LF/NUL）；
    /// 此时不应用任何更改（原子性：要么全部成功，要么全部不变）。
    pub fn apply(
        &self,
        headers: &mut http::HeaderMap,
        env: &PlaceholderEnv,
    ) -> Result<(), String> {
        // 先渲染所有 set / add 的值，检查合法性
        let mut rendered_set: Vec<(HeaderName, http::HeaderValue)> = Vec::with_capacity(self.set.len());
        let mut rendered_add: Vec<(HeaderName, http::HeaderValue)> = Vec::with_capacity(self.add.len());

        for action in &self.set {
            let value = render(&action.value, env);
            let safe = sanitize_header_value(&value)
                .map_err(|e| format!("set header '{}': {e}", action.name))?;
            rendered_set.push((action.name.clone(), safe));
        }

        for action in &self.add {
            let value = render(&action.value, env);
            let safe = sanitize_header_value(&value)
                .map_err(|e| format!("add header '{}': {e}", action.name))?;
            rendered_add.push((action.name.clone(), safe));
        }

        // 渲染全部成功后再应用变更（保证原子性）
        for name in &self.remove {
            headers.remove(name);
        }
        for (name, value) in rendered_set {
            headers.insert(name, value);
        }
        for (name, value) in rendered_add {
            // append 不覆盖已有值，而是增加一个同名头
            headers.append(name, value);
        }

        Ok(())
    }
}

/// 编译一组 HeaderAction：预解析 HeaderName，值保留模板字符串。
fn compile_actions(
    entries: &[HeaderEntryConfig],
    op: &'static str,
) -> Result<Vec<HeaderAction>, String> {
    let mut result = Vec::with_capacity(entries.len());
    for (idx, entry) in entries.iter().enumerate() {
        let name = HeaderName::from_bytes(entry.name.as_bytes())
            .map_err(|e| format!("{op}[{idx}] name '{}': {e}", entry.name))?;
        if entry.value.is_empty() {
            return Err(format!(
                "{op}[{idx}] value must not be empty for '{}'",
                entry.name
            ));
        }
        // 启动期只做"值中是否有 CR/LF/NUL"的预检
        // （占位符替换后可能引入缺失值，但 sanitize 在执行期会兜底）
        if entry.value.contains('\r') || entry.value.contains('\n') || entry.value.contains('\0') {
            return Err(format!(
                "{op}[{idx}] '{}' value contains illegal CR/LF/NUL",
                entry.name
            ));
        }

        result.push(HeaderAction {
            name,
            value: entry.value.clone(),
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    /// 辅助：构造 PlaceholderEnv（apply 测试用）
    fn make_env() -> PlaceholderEnv {
        PlaceholderEnv {
            request_id: "req-1".into(),
            client_ip: Some("10.0.0.1:8080".parse().expect("addr")),
            method: http::Method::GET,
            uri: "http://example.com/api".parse().expect("uri"),
            version: http::Version::HTTP_11,
            request_headers: HeaderMap::new(),
        }
    }

    /// 辅助：构造最小 TransformPolicyConfig
    fn make_config(
        remove: &[&str],
        set: &[(&str, &str)],
        add: &[(&str, &str)],
    ) -> TransformPolicyConfig {
        let json = format!(
            r#"{{"id":"t1","remove_headers":{:?},"set_headers":[{}],"add_headers":[{}]}}"#,
            remove,
            set.iter()
                .map(|(n, v)| format!(r#"{{"name":"{n}","value":"{v}"}}"#))
                .collect::<Vec<_>>()
                .join(","),
            add.iter()
                .map(|(n, v)| format!(r#"{{"name":"{n}","value":"{v}"}}"#))
                .collect::<Vec<_>>()
                .join(","),
        );
        serde_json::from_str(&json).expect("config")
    }

    /// remove / set / add 都正确应用
    #[test]
    fn all_actions_applied() {
        let config = make_config(
            &["X-Internal"],
            &[("X-Gateway", "gateway-proxy")],
            &[("Via", "gateway")],
        );
        let policy = CompiledTransformPolicy::compile(&config).expect("compile");

        let mut env = make_env();
        env.request_headers.insert(
            http::HeaderName::from_static("x-internal"),
            http::HeaderValue::from_static("secret"),
        );

        let mut headers = env.request_headers.clone();
        policy.apply(&mut headers, &env).expect("apply");

        // 1) 删除生效
        assert!(headers.get("X-Internal").is_none());
        // 2) set 覆盖
        assert_eq!(headers.get("X-Gateway").unwrap().to_str().unwrap(), "gateway-proxy");
        // 3) add 追加
        assert!(headers.contains_key("Via"));
    }

    /// 占位符替换在 apply 期正确执行
    #[test]
    fn placeholders_render_on_apply() {
        let config = make_config(&[], &[("X-Request-Id", "${request_id}")], &[]);
        let policy = CompiledTransformPolicy::compile(&config).expect("compile");

        let env = make_env();
        let mut headers = HeaderMap::new();
        policy.apply(&mut headers, &env).expect("apply");

        assert_eq!(headers.get("X-Request-Id").unwrap(), "req-1");
    }

    /// 重复 ID 拒绝
    #[test]
    fn duplicate_ids_are_rejected() {
        let a = make_config(&[], &[], &[]);
        let mut b = a.clone();
        b.id = "dup".into();
        let mut c = a;
        c.id = "dup".into();
        let configs = vec![b, c];
        assert!(CompiledTransformPolicies::compile(&configs).is_err());
    }

    /// 非法 Header 名在编译期拒绝
    #[test]
    fn invalid_header_name_compile_fails() {
        let config = make_config(&[], &[("bad header", "v")], &[]);
        assert!(CompiledTransformPolicy::compile(&config).is_err());
    }

    /// 空 Header 值在编译期拒绝
    #[test]
    fn empty_header_value_compile_fails() {
        let json = r#"{"id":"t1","set_headers":[{"name":"X-Test","value":""}]}"#;
        let cfg: TransformPolicyConfig = serde_json::from_str(json).expect("deserialize");
        assert!(CompiledTransformPolicy::compile(&cfg).is_err());
    }
}
