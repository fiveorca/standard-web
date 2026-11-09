//! 路径模式与取值模式匹配。
//!
//! 路径使用 Ant 风格通配符：
//! - `**` 匹配零个或多个路径段
//! - `*` 匹配单个路径段内的任意字符
//! - `?` 匹配单个字符
//! - `{name}` 匹配单个路径段
//!
//! 请求头 / 查询参数 / Cookie 的取值使用正则表达式匹配。

use regex::Regex;

/// 编译后的路径模式。
#[derive(Debug, Clone)]
pub struct PathPattern {
    raw: String,
    regex: Regex,
    specificity: u32,
}

impl PathPattern {
    /// 编译路径模式。
    pub fn new(pattern: &str) -> Result<Self, String> {
        let normalized = if pattern.is_empty() {
            "/**"
        } else if !pattern.starts_with('/') {
            // 允许省略前导斜杠
            &format!("/{}", pattern)
        } else {
            pattern
        };
        let regex_src = glob_to_regex(normalized);
        let regex =
            Regex::new(&regex_src).map_err(|e| format!("invalid path pattern `{pattern}`: {e}"))?;
        Ok(Self {
            raw: normalized.to_string(),
            regex,
            specificity: compute_specificity(normalized),
        })
    }

    /// 是否匹配给定路径。
    pub fn is_match(&self, path: &str) -> bool {
        self.regex.is_match(path)
    }

    /// 原始模式字符串。
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// 模式具体程度：字面量越多、通配符越少，具体程度越高。
    pub fn specificity(&self) -> u32 {
        self.specificity
    }
}

/// 将 Ant 风格通配符转换为正则表达式。
pub fn glob_to_regex(glob: &str) -> String {
    let chars: Vec<char> = glob.chars().collect();
    let mut out = String::with_capacity(glob.len() * 2 + 4);
    out.push('^');
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '*' => {
                let double = i + 1 < chars.len() && chars[i + 1] == '*';
                if double {
                    let at_end = i + 2 == chars.len();
                    if at_end {
                        if out.ends_with('/') {
                            out.pop();
                            out.push_str("(?:/.*)?");
                        } else {
                            out.push_str(".*");
                        }
                        i += 2;
                    } else if i + 2 < chars.len() && chars[i + 2] == '/' {
                        out.push_str("(?:.*/)?");
                        i += 3;
                    } else {
                        out.push_str(".*");
                        i += 2;
                    }
                } else {
                    out.push_str("[^/]*");
                    i += 1;
                }
            }
            '?' => {
                out.push_str("[^/]");
                i += 1;
            }
            '{' => {
                if let Some(offset) = chars[i..].iter().position(|c| *c == '}') {
                    let inner: String = chars[i + 1..i + offset].iter().collect();
                    let body = match inner.split_once(':') {
                        Some((_, rx)) => rx.to_string(),
                        None => "[^/]+".to_string(),
                    };
                    out.push('(');
                    out.push_str(&body);
                    out.push(')');
                    i += offset + 1;
                } else {
                    out.push_str("\\{");
                    i += 1;
                }
            }
            '.' => {
                out.push_str("\\.");
                i += 1;
            }
            c if c.is_ascii_alphanumeric()
                || c == '/'
                || c == '-'
                || c == '_'
                || c == '~'
                || c == '%'
                || c == ':'
                || c == '@' =>
            {
                out.push(c);
                i += 1;
            }
            other => {
                out.push_str(&regex::escape(&other.to_string()));
                i += 1;
            }
        }
    }
    out.push('$');
    out
}

fn compute_specificity(pattern: &str) -> u32 {
    let mut score: u32 = 0;
    for segment in pattern.split('/') {
        if segment.is_empty() {
            continue;
        }
        if segment == "**" {
            continue;
        }
        if segment.contains('*') || segment.contains('?') || segment.contains('{') {
            score += 2;
        } else {
            score += 10 + segment.chars().count() as u32;
        }
    }
    score
}

/// 取值模式：始终按正则表达式匹配。
#[derive(Debug, Clone)]
pub struct ValuePattern {
    raw: String,
    regex: Regex,
}

impl ValuePattern {
    pub fn new(pattern: &str) -> Result<Self, String> {
        let regex =
            Regex::new(pattern).map_err(|e| format!("invalid value pattern `{pattern}`: {e}"))?;
        Ok(Self {
            raw: pattern.to_string(),
            regex,
        })
    }

    pub fn is_match(&self, value: &str) -> bool {
        self.regex.is_match(value)
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }
}

/// 域名模式：使用 `*` / `**` 通配符，大小写不敏感。
#[derive(Debug, Clone)]
pub struct HostPattern {
    raw: String,
    regex: Regex,
}

impl HostPattern {
    pub fn new(pattern: &str) -> Result<Self, String> {
        let lower = pattern.trim().to_ascii_lowercase();
        let regex = Regex::new(&glob_to_regex(&lower))
            .map_err(|e| format!("invalid host pattern `{pattern}`: {e}"))?;
        Ok(Self { raw: lower, regex })
    }

    pub fn is_match(&self, host: &str) -> bool {
        self.regex.is_match(&host.to_ascii_lowercase())
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_matching() {
        let p = PathPattern::new("/api/users/**").unwrap();
        assert!(p.is_match("/api/users"));
        assert!(p.is_match("/api/users/1"));
        assert!(p.is_match("/api/users/1/orders"));
        assert!(!p.is_match("/api/other"));

        let p = PathPattern::new("/api/*/detail").unwrap();
        assert!(p.is_match("/api/42/detail"));
        assert!(!p.is_match("/api/42/x/detail"));

        let p = PathPattern::new("/**").unwrap();
        assert!(p.is_match("/"));
        assert!(p.is_match("/anything/here"));

        let p = PathPattern::new("/api/{version}/users").unwrap();
        assert!(p.is_match("/api/v1/users"));
        assert!(!p.is_match("/api/v1/v2/users"));
    }

    #[test]
    fn specificity_ordering() {
        let specific = PathPattern::new("/api/users/1").unwrap();
        let generic = PathPattern::new("/api/**").unwrap();
        assert!(specific.specificity() > generic.specificity());
    }

    #[test]
    fn value_patterns() {
        let p = ValuePattern::new(r"^application/json$").unwrap();
        assert!(p.is_match("application/json"));
        assert!(!p.is_match("text/html"));

        let p = ValuePattern::new(r"^v\d+$").unwrap();
        assert!(p.is_match("v12"));
        assert!(!p.is_match("12"));
    }
}
