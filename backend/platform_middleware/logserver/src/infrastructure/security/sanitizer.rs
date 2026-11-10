// ! 安全与脱敏

use crate::config::SecurityConfig;
use crate::domain::LogEvent;
use std::collections::HashMap;
use std::sync::Arc;

/// 脱敏处理器
#[derive(Debug, Clone)]
pub struct Sanitizer {
    config: Arc<SecurityConfig>,
}

impl Sanitizer {
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// 对 message 和 attributes 中的敏感字段进行脱敏
    pub fn sanitize(&self, event: &mut LogEvent) {
        if !self.config.sanitize_enabled {
            return;
        }
        let mask = self.config.sanitize_mask.as_str();
        let sensitive: Vec<String> = self
            .config
            .sensitive_fields
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        // attributes 脱敏
        if let Some(ref mut attrs) = event.attributes {
            sanitize_map(attrs, &sensitive, mask);
        }

        // exception message 也可能包含敏感信息（简单处理，只对 known 敏感字段名的模式做掩码）
        if let Some(ref mut exc) = event.exception {
            if let Some(ref mut msg) = exc.message {
                *msg = sanitize_string(msg, &sensitive, mask);
            }
            if let Some(ref mut st) = exc.stack_trace {
                *st = sanitize_string(st, &sensitive, mask);
            }
        }
    }

    /// 检查 attributes 或 message 是否包含敏感字段名（用于告警或拒绝）
    pub fn contains_sensitive_field_name(&self, event: &LogEvent) -> bool {
        let sensitive: Vec<String> = self
            .config
            .sensitive_fields
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        if let Some(attrs) = &event.attributes {
            for k in attrs.keys() {
                let lk = k.to_lowercase();
                for s in &sensitive {
                    if lk.contains(s.as_str()) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

fn sanitize_map(map: &mut HashMap<String, String>, sensitive: &[String], mask: &str) {
    let keys: Vec<String> = map.keys().cloned().collect();
    for k in keys {
        let lk = k.to_lowercase();
        let hit = sensitive.iter().any(|s| lk.contains(s.as_str()));
        if hit {
            if let Some(v) = map.get_mut(&k) {
                *v = mask.to_string();
            }
        } else {
            // value 内部也可能包含敏感字段（JSON key=value 形式）
            if let Some(v) = map.get_mut(&k) {
                *v = sanitize_string(v, sensitive, mask);
            }
        }
    }
}

fn sanitize_string(input: &str, sensitive: &[String], mask: &str) -> String {
    let mut out = input.to_string();
    // 简单 key=value 模式替换
    for key in sensitive {
        let pattern = format!("{}=", key.as_str());
        if let Some(pos) = out.find(&pattern) {
            let start = pos + pattern.len();
            let rest = &out[start..];
            let end = rest
                .find(|c: char| c == '&' || c == ',' || c == ' ' || c == '\n')
                .unwrap_or(rest.len());
            out.replace_range(start..start + end, mask);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::LogLevel;
    use chrono::Utc;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn make_event() -> LogEvent {
        LogEvent::new(
            Uuid::new_v4(),
            Utc::now(),
            LogLevel::Error,
            "auth-svc".into(),
            "login failed".into(),
        )
    }

    #[test]
    fn sanitize_password_field() {
        let mut e = make_event();
        let mut attrs = HashMap::new();
        attrs.insert("password".into(), "my_secret_pw".into());
        attrs.insert("username".into(), "alice".into());
        e.attributes = Some(attrs);

        let cfg = SecurityConfig::default();
        let s = Sanitizer::new(cfg);
        s.sanitize(&mut e);

        let attrs = e.attributes.unwrap();
        assert_eq!(attrs.get("password").unwrap(), "***REDACTED***");
        assert_eq!(attrs.get("username").unwrap(), "alice");
    }

    #[test]
    fn sanitize_disabled_leaves_intact() {
        let mut e = make_event();
        let mut attrs = HashMap::new();
        attrs.insert("secret".into(), "abc".into());
        e.attributes = Some(attrs);

        let mut cfg = SecurityConfig::default();
        cfg.sanitize_enabled = false;
        let s = Sanitizer::new(cfg);
        s.sanitize(&mut e);

        assert_eq!(
            e.attributes.unwrap().get("secret").unwrap(),
            "abc"
        );
    }
}
