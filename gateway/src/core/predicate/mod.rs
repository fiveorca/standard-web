//! 路由断言（Predicate）引擎。
//!
//! 支持的断言类型：Path、Host、Method、Header、Query、Cookie、RemoteAddr、
//! After、Before、Between。多个断言之间是 AND 关系。

use std::net::IpAddr;

use chrono::{DateTime, NaiveDate, Utc};
use http::{HeaderMap, HeaderName, Method};
use ipnet::IpNet;

use crate::config::model::{PredicateObject, PredicateSpec};
use crate::utils::pattern::{HostPattern, PathPattern, ValuePattern};

/// 断言匹配所需的请求视图。
pub struct PredicateRequest<'a> {
    pub method: &'a Method,
    pub path: &'a str,
    pub host: Option<&'a str>,
    pub headers: &'a HeaderMap,
    pub query: Option<&'a str>,
    pub client_ip: Option<IpAddr>,
    pub now: DateTime<Utc>,
}

/// 单个断言。
#[derive(Debug, Clone)]
pub enum Predicate {
    Path(PathPattern),
    Host(HostPattern),
    Method(Vec<Method>),
    Header {
        name: HeaderName,
        value: Option<ValuePattern>,
    },
    Query {
        name: String,
        value: Option<ValuePattern>,
    },
    Cookie {
        name: String,
        value: Option<ValuePattern>,
    },
    RemoteAddr(Vec<IpNet>),
    After(DateTime<Utc>),
    Before(DateTime<Utc>),
    Between(DateTime<Utc>, DateTime<Utc>),
}

impl Predicate {
    /// 从配置描述解析断言。
    pub fn parse(spec: &PredicateSpec) -> Result<Self, String> {
        match spec {
            PredicateSpec::Short(text) => Self::parse_short(text),
            PredicateSpec::Full(obj) => Self::parse_object(obj),
        }
    }

    fn parse_short(text: &str) -> Result<Self, String> {
        let (name, value) = text
            .split_once('=')
            .ok_or_else(|| format!("predicate must be in `Name=Value` form: `{text}`"))?;
        let name = name.trim();
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "path" => Ok(Predicate::Path(PathPattern::new(value)?)),
            "host" => Ok(Predicate::Host(HostPattern::new(value)?)),
            "method" => {
                let methods = value
                    .split(',')
                    .map(|m| {
                        Method::from_bytes(m.trim().as_bytes())
                            .map_err(|e| format!("invalid HTTP method `{m}`: {e}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if methods.is_empty() {
                    return Err("Method predicate requires at least one method".to_string());
                }
                Ok(Predicate::Method(methods))
            }
            "header" => {
                let (header_name, pattern) = split_pair(value);
                let name = HeaderName::from_bytes(header_name.as_bytes())
                    .map_err(|e| format!("invalid header name `{header_name}`: {e}"))?;
                Ok(Predicate::Header {
                    name,
                    value: pattern.map(|p| ValuePattern::new(&p)).transpose()?,
                })
            }
            "query" => {
                let (key, pattern) = split_pair(value);
                Ok(Predicate::Query {
                    name: key,
                    value: pattern.map(|p| ValuePattern::new(&p)).transpose()?,
                })
            }
            "cookie" => {
                let (key, pattern) = split_pair(value);
                Ok(Predicate::Cookie {
                    name: key,
                    value: pattern.map(|p| ValuePattern::new(&p)).transpose()?,
                })
            }
            "remoteaddr" => {
                let mut nets = Vec::new();
                for part in value.split(',') {
                    if part.trim().is_empty() {
                        continue;
                    }
                    nets.push(
                        part.trim()
                            .parse::<IpNet>()
                            .map_err(|e| format!("invalid CIDR `{}`: {e}", part.trim()))?,
                    );
                }
                Ok(Predicate::RemoteAddr(nets))
            }
            "after" => Ok(Predicate::After(parse_timestamp(value)?)),
            "before" => Ok(Predicate::Before(parse_timestamp(value)?)),
            "between" => {
                let (start, end) = value
                    .split_once(',')
                    .ok_or_else(|| "Between requires `start,end`".to_string())?;
                let start = parse_timestamp(start)?;
                let end = parse_timestamp(end)?;
                if start >= end {
                    return Err("Between start must be before end".to_string());
                }
                Ok(Predicate::Between(start, end))
            }
            other => Err(format!("unsupported predicate `{other}`")),
        }
    }

    fn parse_object(obj: &PredicateObject) -> Result<Self, String> {
        let name = obj.name.to_ascii_lowercase();
        // 支持 `{name: Path, args: {pattern: "/api/**"}}` 与 `{name: Path, args: "/api/**"}`
        let inline = match &obj.args {
            serde_yaml::Value::String(s) => Some(s.clone()),
            serde_yaml::Value::Mapping(map) => map
                .get(serde_yaml::Value::String("value".into()))
                .or_else(|| map.get(serde_yaml::Value::String("pattern".into())))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            _ => None,
        };

        match name.as_str() {
            "path" => Ok(Predicate::Path(PathPattern::new(
                inline
                    .as_deref()
                    .ok_or("Path predicate requires a pattern")?,
            )?)),
            "host" => Ok(Predicate::Host(HostPattern::new(
                inline
                    .as_deref()
                    .ok_or("Host predicate requires a pattern")?,
            )?)),
            "method" => {
                let value = inline.ok_or("Method predicate requires methods")?;
                Self::parse_short(&format!("Method={value}"))
            }
            "header" | "query" | "cookie" => {
                let value = inline.ok_or("predicate requires a value")?;
                Self::parse_short(&format!("{name}={value}"))
            }
            "remoteaddr" => {
                let value = inline.ok_or("RemoteAddr predicate requires CIDRs")?;
                Self::parse_short(&format!("RemoteAddr={value}"))
            }
            "after" | "before" | "between" => {
                let value = inline.ok_or("time predicate requires a timestamp")?;
                Self::parse_short(&format!("{name}={value}"))
            }
            other => Err(format!("unsupported predicate `{other}`")),
        }
    }

    /// 判断请求是否满足断言。
    pub fn matches(&self, req: &PredicateRequest<'_>) -> bool {
        match self {
            Predicate::Path(pattern) => pattern.is_match(req.path),
            Predicate::Host(pattern) => req
                .host
                .map(|h| pattern.is_match(crate::utils::http::host_without_port(h)))
                .unwrap_or(false),
            Predicate::Method(methods) => methods.iter().any(|m| m == req.method),
            Predicate::Header { name, value } => match req.headers.get(name) {
                None => false,
                Some(raw) => match value {
                    None => true,
                    Some(pattern) => raw.to_str().map(|v| pattern.is_match(v)).unwrap_or(false),
                },
            },
            Predicate::Query { name, value } => {
                let query = req.query.unwrap_or_default();
                for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
                    if k == name.as_str() {
                        match value {
                            None => return true,
                            Some(pattern) if pattern.is_match(&v) => return true,
                            _ => {}
                        }
                    }
                }
                false
            }
            Predicate::Cookie { name, value } => {
                let Some(cookie_header) = req.headers.get(http::header::COOKIE) else {
                    return false;
                };
                let Ok(raw) = cookie_header.to_str() else {
                    return false;
                };
                for pair in raw.split(';') {
                    let pair = pair.trim();
                    let Some((k, v)) = pair.split_once('=') else {
                        continue;
                    };
                    if k.trim() == name {
                        return match value {
                            None => true,
                            Some(pattern) => pattern.is_match(v.trim()),
                        };
                    }
                }
                false
            }
            Predicate::RemoteAddr(nets) => match req.client_ip {
                Some(ip) => nets.iter().any(|net| net.contains(&ip)),
                None => false,
            },
            Predicate::After(ts) => req.now > *ts,
            Predicate::Before(ts) => req.now < *ts,
            Predicate::Between(start, end) => req.now >= *start && req.now <= *end,
        }
    }

    /// 路径断言的模式（用于计算路由具体程度）。
    pub fn path_pattern(&self) -> Option<&PathPattern> {
        match self {
            Predicate::Path(p) => Some(p),
            _ => None,
        }
    }

    /// 人类可读描述。
    pub fn describe(&self) -> String {
        match self {
            Predicate::Path(p) => format!("Path={}", p.raw()),
            Predicate::Host(p) => format!("Host={}", p.raw()),
            Predicate::Method(methods) => format!(
                "Method={}",
                methods
                    .iter()
                    .map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Predicate::Header { name, value } => match value {
                Some(v) => format!("Header={},{}", name.as_str(), v.raw()),
                None => format!("Header={}", name.as_str()),
            },
            Predicate::Query { name, value } => match value {
                Some(v) => format!("Query={},{}", name, v.raw()),
                None => format!("Query={name}"),
            },
            Predicate::Cookie { name, value } => match value {
                Some(v) => format!("Cookie={},{}", name, v.raw()),
                None => format!("Cookie={name}"),
            },
            Predicate::RemoteAddr(nets) => format!(
                "RemoteAddr={}",
                nets.iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Predicate::After(ts) => format!("After={}", ts.to_rfc3339()),
            Predicate::Before(ts) => format!("Before={}", ts.to_rfc3339()),
            Predicate::Between(a, b) => format!("Between={},{}", a.to_rfc3339(), b.to_rfc3339()),
        }
    }
}

fn split_pair(value: &str) -> (String, Option<String>) {
    match value.split_once(',') {
        Some((name, pattern)) => (name.trim().to_string(), Some(pattern.trim().to_string())),
        None => (value.trim().to_string(), None),
    }
}

/// 解析时间戳：支持 RFC3339、`YYYY-MM-DD` 以及 `@<unix-seconds>`。
pub fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, String> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('@') {
        let seconds: i64 = rest
            .parse()
            .map_err(|_| format!("invalid unix timestamp `{value}`"))?;
        return DateTime::from_timestamp(seconds, 0)
            .ok_or_else(|| format!("invalid unix timestamp `{value}`"));
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(value) {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Ok(date) = NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        let dt = date
            .and_hms_opt(0, 0, 0)
            .ok_or_else(|| format!("invalid date `{value}`"))?;
        return Ok(DateTime::from_naive_utc_and_offset(dt, Utc));
    }
    Err(format!("invalid timestamp `{value}`"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn req<'a>(
        method: &'a Method,
        path: &'a str,
        headers: &'a HeaderMap,
        query: Option<&'a str>,
    ) -> PredicateRequest<'a> {
        PredicateRequest {
            method,
            path,
            host: Some("api.example.com"),
            headers,
            query,
            client_ip: Some("10.1.2.3".parse().unwrap()),
            now: Utc.with_ymd_and_hms(2024, 6, 1, 12, 0, 0).unwrap(),
        }
    }

    #[test]
    fn path_predicate() {
        let p = Predicate::parse_short("Path=/api/users/**").unwrap();
        let headers = HeaderMap::new();
        let method = Method::GET;
        assert!(p.matches(&req(&method, "/api/users/1", &headers, None)));
        assert!(!p.matches(&req(&method, "/api/orders", &headers, None)));
    }

    #[test]
    fn method_and_header_and_query() {
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant", "acme".parse().unwrap());
        let method = Method::GET;
        let p = Predicate::parse_short("Method=GET,POST").unwrap();
        assert!(p.matches(&req(&method, "/", &headers, None)));
        let p = Predicate::parse_short("Header=X-Tenant,^acme$").unwrap();
        assert!(p.matches(&req(&method, "/", &headers, None)));
        let p = Predicate::parse_short("Query=page,^2$").unwrap();
        assert!(p.matches(&req(&method, "/", &headers, Some("page=2&size=10"))));
        assert!(!p.matches(&req(&method, "/", &headers, Some("page=3"))));
        assert!(!p.matches(&req(&method, "/", &headers, Some("size=2"))));
    }

    #[test]
    fn remote_addr_predicate() {
        let p = Predicate::parse_short("RemoteAddr=10.0.0.0/8,192.168.1.0/24").unwrap();
        let headers = HeaderMap::new();
        let method = Method::GET;
        assert!(p.matches(&req(&method, "/", &headers, None)));
    }

    #[test]
    fn time_predicates() {
        let headers = HeaderMap::new();
        let method = Method::GET;
        let after = Predicate::parse_short("After=2024-01-01T00:00:00Z").unwrap();
        assert!(after.matches(&req(&method, "/", &headers, None)));
        let before = Predicate::parse_short("Before=2024-01-01T00:00:00Z").unwrap();
        assert!(!before.matches(&req(&method, "/", &headers, None)));
        let between =
            Predicate::parse_short("Between=2024-01-01T00:00:00Z,2025-01-01T00:00:00Z").unwrap();
        assert!(between.matches(&req(&method, "/", &headers, None)));
    }

    #[test]
    fn cookie_predicate() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "session=abc123; theme=dark".parse().unwrap());
        let method = Method::GET;
        let p = Predicate::parse_short("Cookie=session,^abc").unwrap();
        assert!(p.matches(&req(&method, "/", &headers, None)));
    }

    #[test]
    fn host_predicate() {
        let p = Predicate::parse_short("Host=**.example.com").unwrap();
        let headers = HeaderMap::new();
        let method = Method::GET;
        assert!(p.matches(&req(&method, "/", &headers, None)));
    }
}
