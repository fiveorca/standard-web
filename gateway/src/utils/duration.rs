//! Duration 的序列化 / 反序列化辅助。
//!
//! 配置中支持 `3s`、`500ms`、`1m`、`2h`、`1.5s` 或者纯数字（单位：秒）。

use std::time::Duration;

use serde::{Deserialize, Deserializer, Serializer};

/// 解析人类可读的 duration 字符串。
pub fn parse_duration(input: &str) -> Result<Duration, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }

    let (number_part, unit) = split_number_unit(s)?;
    let value: f64 = number_part
        .parse()
        .map_err(|_| format!("invalid duration number: {number_part}"))?;
    if value < 0.0 || !value.is_finite() {
        return Err(format!("invalid duration value: {number_part}"));
    }

    let millis = match unit.as_str() {
        "" | "s" | "sec" | "secs" | "second" | "seconds" => value * 1000.0,
        "ms" | "milli" | "millis" | "millisecond" | "milliseconds" => value,
        "m" | "min" | "mins" | "minute" | "minutes" => value * 60_000.0,
        "h" | "hr" | "hour" | "hours" => value * 3_600_000.0,
        "d" | "day" | "days" => value * 86_400_000.0,
        other => return Err(format!("unknown duration unit: {other}")),
    };

    Ok(Duration::from_millis(millis.round() as u64))
}

fn split_number_unit(s: &str) -> Result<(String, String), String> {
    let idx = s.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(s.len());
    let (num, unit) = s.split_at(idx);
    if num.trim().is_empty() {
        return Err(format!("invalid duration: {s}"));
    }
    Ok((num.trim().to_string(), unit.trim().to_ascii_lowercase()))
}

/// 将 Duration 格式化为配置字符串。
pub fn format_duration(d: &Duration) -> String {
    if d.is_zero() {
        "0s".to_string()
    } else if d.subsec_nanos() == 0 {
        format!("{}s", d.as_secs())
    } else {
        format!("{}ms", d.as_millis())
    }
}

/// 反序列化一个必填 duration。
pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let value = ValueOrNumber::deserialize(deserializer)?;
    value.to_duration().map_err(serde::de::Error::custom)
}

/// 反序列化一个可选 duration。
pub fn deserialize_opt<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<ValueOrNumber>::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(v) => v.to_duration().map(Some).map_err(serde::de::Error::custom),
    }
}

/// 序列化为字符串。
pub fn serialize<S>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format_duration(value))
}

/// 序列化可选值。
pub fn serialize_opt<S>(value: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(v) => serializer.serialize_str(&format_duration(v)),
        None => serializer.serialize_none(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ValueOrNumber {
    Str(String),
    Int(u64),
    Float(f64),
}

impl ValueOrNumber {
    fn to_duration(&self) -> Result<Duration, String> {
        match self {
            ValueOrNumber::Str(s) => parse_duration(s),
            ValueOrNumber::Int(i) => Ok(Duration::from_secs(*i)),
            ValueOrNumber::Float(f) => {
                if *f < 0.0 {
                    Err("negative duration".to_string())
                } else {
                    Ok(Duration::from_millis((f * 1000.0).round() as u64))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units() {
        assert_eq!(parse_duration("3s").unwrap(), Duration::from_secs(3));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("1.5s").unwrap(), Duration::from_millis(1500));
        assert_eq!(parse_duration("10").unwrap(), Duration::from_secs(10));
        assert!(parse_duration("10x").is_err());
    }

    #[test]
    fn formats() {
        assert_eq!(format_duration(&Duration::from_secs(3)), "3s");
        assert_eq!(format_duration(&Duration::from_millis(1500)), "1500ms");
    }
}
