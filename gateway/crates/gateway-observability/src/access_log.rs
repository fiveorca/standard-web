//! AccessLog —— 每次请求结束后输出一条 JSON 访问日志。
//!
//! 访问日志是网关可观测性的核心组件。每个请求处理完毕后，
//! Runtime 会调用 `AccessLog::emit(ctx)` 输出一条结构化 JSON 日志。
//!
//! # 日志内容
//!
//! 对应需求文档 4.10 节规定的字段：
//!   - timestamp：自动生成
//!   - request_id：从 RequestContext 取
//!   - trace_id：从 RequestContext 取（Phase 1 可能为 None）
//!   - method, host, path, query
//!   - matched_route_id
//!   - selected_upstream
//!   - response_status
//!   - request_duration_ms
//!   - upstream_duration_ms
//!   - error_code / error_message（如果有）
//!
//! # 脱敏约束（需求文档 4.10）
//!
//! 严禁在访问日志中记录：
//!   - 密码、完整 JWT、API Key、私钥
//!   - 未脱敏的敏感用户数据
//!
//! Phase 1 中我们不记录 Request Body 和 Response Body，
//! 也不记录完整 URL query（只记录 query 字符串）。

use serde::Serialize;

use gateway_core::RequestContext;

/// 访问日志 JSON 条目结构。
///
/// `emit_to_console` 会把这个结构体序列化为 JSON 后输出。
#[derive(Debug, Serialize)]
pub struct AccessLogEntry {
    /// ISO 8601 格式时间戳（UTC）。由手工实现
    timestamp: String,

    // ---- 请求标识 ---- //
    /// 请求 ID，必须有值
    request_id: String,
    /// 分布式追踪 ID，可能为 None
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,

    // ---- 请求基本信息 ---- //
    method: String,
    host: String,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_ip: Option<String>,

    // ---- 路由 / 上游 ---- //
    #[serde(skip_serializing_if = "Option::is_none")]
    matched_route_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_endpoint: Option<String>,

    // ---- 响应 ---- //
    status_code: Option<u16>,

    // ---- 时间（毫秒）---- //
    request_duration_ms: u64,
    upstream_duration_ms: u64,

    // ---- 错误 ---- //
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
}

/// 访问日志入口。
pub struct AccessLog;

impl AccessLog {
    /// 根据 RequestContext 构造 AccessLogEntry。
    pub fn build_entry(ctx: &RequestContext) -> AccessLogEntry {
        AccessLogEntry {
            timestamp: format_timestamp(),
            request_id: ctx.request_id.as_str().to_string(),
            trace_id: ctx.trace_id.clone(),
            method: ctx.method.clone(),
            host: ctx.host.clone(),
            path: ctx.path.clone(),
            query: ctx.query.clone(),
            client_ip: ctx.client_ip.map(|a| a.ip().to_string()),
            matched_route_id: ctx.matched_route.as_ref().map(|r| r.id.clone()),
            selected_endpoint: ctx.selected_endpoint.as_ref().map(|ep| ep.address()),
            status_code: ctx.status_code,
            request_duration_ms: ctx.total_duration_ms(),
            upstream_duration_ms: ctx.upstream_duration_ms(),
            error_code: ctx.error_code.clone(),
            error_message: ctx.error_message.clone(),
        }
    }

    /// 直接输出到 tracing 的 info! 级别。
    ///
    /// 用 `tracing::info!` 输出 JSON 日志，与全局 tracing subscriber
    /// 的 JSON 格式一致，采集端统一处理。
    pub fn emit(ctx: &RequestContext) {
        let entry = Self::build_entry(ctx);
        // 用 serde_json 把结构体序列化成 JSON 字符串
        match serde_json::to_string(&entry) {
            Ok(json) => {
                // tracing 的 instrument! 或 event! 都会输出到 subscriber
                tracing::info!(target: "access_log", "{}", json);
            },
            Err(e) => {
                tracing::error!(
                    target: "access_log",
                    error = e.to_string(),
                    "failed to serialize access log entry"
                );
            },
        }
    }
}

/// 生成 ISO 8601 UTC 时间戳。
///
/// Phase 1 不引入 chrono 依赖，用 std::time::SystemTime + 格式化手工拼。
/// 这虽然不够完美但足够日志使用；Phase 5 加 Metrics/Tracing 时
/// 会自然引入 chrono。
fn format_timestamp() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();

    // 把 Unix epoch seconds 转换成 UTC 年月日时分秒。
    // 算法：Zeller's 或直接用 div_mod。为了简洁，我们用简单的
    // Unix seconds → UTC date 转换。
    let (year, month, day, hour, min, sec) = unix_to_utc(secs as i64);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

/// 简化版 Unix epoch seconds → UTC 日期时间转换。
/// 足够 Phase 1 的访问日志精度。
fn unix_to_utc(epoch: i64) -> (i32, u32, u32, u32, u32, u32) {
    // 1 秒 = 1 秒。用 div/mod 层层剥离。
    let mut seconds = epoch;

    let sec = (seconds % 60) as u32;
    seconds /= 60;
    let min = (seconds % 60) as u32;
    seconds /= 60;
    let hour = (seconds % 24) as u32;
    let mut days = seconds / 24;

    // 1970-01-01 是 Thursday（day of week = 4），但我们不需要 weekday

    // 从 1970 年开始累加年份直到 days < 该年天数
    let mut year: i32 = 1970;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    // 从 1 月开始累加月份
    let days_in_months = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month_idx: u32 = 0;
    loop {
        let dim = if month_idx == 1 && is_leap_year(year) {
            29
        } else {
            days_in_months[month_idx as usize]
        };
        if days < dim {
            break;
        }
        days -= dim;
        month_idx += 1;
    }

    let month = month_idx + 1; // 转为 1-based
    let day = days as u32 + 1; // 转为 1-based

    (year, month, day, hour, min, sec)
}

fn is_leap_year(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_epoch_1970_01_01() {
        let (y, m, d, h, mi, s) = unix_to_utc(0);
        assert_eq!((y, m, d, h, mi, s), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn unix_epoch_2024_06_15_12_30_45() {
        // 2024-06-15 12:30:45 UTC
        let (y, m, d, h, mi, s) = unix_to_utc(1718454645);
        assert_eq!(y, 2024);
        assert_eq!(m, 6);
        assert_eq!(d, 15);
        assert_eq!(h, 12);
        assert_eq!(mi, 30);
        assert_eq!(s, 45);
    }

    #[test]
    fn is_leap_year_correct() {
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(2023));
        assert!(!is_leap_year(1900));
        assert!(is_leap_year(2000));
    }
}
