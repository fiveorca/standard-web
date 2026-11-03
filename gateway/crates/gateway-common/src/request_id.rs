//! 请求 ID（RequestId）。
//!
//! 请求 ID 是在网关请求入口生成的全局唯一标识符，用于：
//!   - 日志串联（access log、tracing）
//!   - 排查某个特定请求的完整处理路径
//!   - HTTP 响应头 `X-Request-Id` 传递给调用方
//!
//! # 设计决策
//!
//! - 内部用 `uuid::Uuid::new_v4()` 生成随机 UUID，不包含任何敏感信息。
//! - 对外暴露为格式化后的 `String`（去掉连字符的 32 位小写十六进制），
//!   这样在 URL/Header/日志中都很简洁。
//! - 实现了 `Display`、`Deref<Target=str>`，方便在格式化字符串中直接使用。

use std::fmt;
use std::ops::Deref;

use serde::{Deserialize, Serialize};

/// 请求 ID 封装。
///
/// 通过 [`RequestId::new`] 生成新的请求 ID，也可以通过
/// [`RequestId::from_string`] 从上游 Header（如 `X-Request-Id`）
/// 解析已有的请求 ID。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(String);

impl RequestId {
    /// 生成一个新的随机请求 ID（UUID v4，去掉连字符）。
    ///
    /// 底层调用 `uuid::Uuid::new_v4()`，返回一个全局唯一的 128-bit 值，
    /// 再通过 `to_string().replace('-', "")` 移除连字符。
    pub fn new() -> Self {
        // uuid::Uuid::new_v4() —— 标准库级别的随机 UUID，RFC 4122 v4。
        // 返回 Uuid 类型，其 Display 实现会输出形如 "550e8400-e29b-41d4-a716-446655440000" 的字符串。
        let raw = uuid::Uuid::new_v4().to_string();
        // 去掉连字符后长度为 32，例如 "550e8400e29b41d4a716446655440000"
        Self(raw.replace('-', ""))
    }

    /// 从已有字符串构造 RequestId。
    ///
    /// 主要用于从 `X-Request-Id` Header 中提取上游传递的请求 ID，
    /// 此时不重新生成，而是直接透传（保持整条链的 ID 一致）。
    pub fn from_string(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// 取得内部字符串的引用。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Deref for RequestId {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for RequestId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<&str> for RequestId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for RequestId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_generates_32_chars_without_hyphens() {
        let id = RequestId::new();
        assert_eq!(id.as_str().len(), 32);
        assert!(!id.as_str().contains('-'));
    }

    #[test]
    fn new_is_unique() {
        let a = RequestId::new();
        let b = RequestId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn display_deref_asref_all_work() {
        let id = RequestId::from_string("abc123");
        assert_eq!(format!("{}", id), "abc123");
        assert_eq!(id.deref(), "abc123");
        assert_eq!(id.as_ref(), "abc123");
    }
}
