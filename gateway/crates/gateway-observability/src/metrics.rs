//! Prometheus 兼容的 Metrics 注册表（Phase 5 可观测性）。
//!
//! # 为什么不引入 prometheus crate
//!
//! 网关只需要最基础的 counter / histogram 与文本导出格式，自己实现
//! 只需一个文件、无额外编译依赖，也不会因为第三方 crate 的全局注册表
//! 而产生隐藏的单例状态。渲染格式严格遵循 Prometheus 文本协议
//! （`text/plain; version=0.0.4`）。
//!
//! # 线程安全
//!
//! - series 注册表用 `RwLock<BTreeMap<...>>`：读多写少，新 series 只在
//!   第一次出现时写入；
//! - 每个 series 的计数用 `AtomicU64`：热路径只做一次原子累加，不加锁。
//!
//! # 指标命名
//!
//! 遵循 Prometheus 约定：
//!   - counter 以 `_total` 结尾
//!   - histogram 以毫秒为单位时后缀 `_milliseconds`
//!   - 标签名使用 snake_case

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use gateway_core::RequestContext;

/// 延迟直方图的分桶上界（毫秒）。
///
/// 覆盖从 1ms 到 30s，足以区分本地缓存命中、正常上游响应与慢请求。
/// `+Inf` 桶不单独存储，渲染时用总次数补上。
const DURATION_BUCKETS_MS: [u64; 12] = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 30000];

/// 全局单例。`OnceLock` 保证多线程下只初始化一次。
static GLOBAL_METRICS: OnceLock<Metrics> = OnceLock::new();

/// 单个直方图 series 的累计状态。
struct HistogramState {
    /// 每个桶的累计计数（与 `DURATION_BUCKETS_MS` 一一对应）
    buckets: Vec<AtomicU64>,
    /// 所有观测值之和（毫秒）
    sum: AtomicU64,
    /// 观测总次数
    count: AtomicU64,
}

impl HistogramState {
    /// 构造一个全零的直方图状态。
    fn new() -> Self {
        Self {
            buckets: (0..DURATION_BUCKETS_MS.len()).map(|_| AtomicU64::new(0)).collect(),
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

/// Prometheus Metrics 注册表。
///
/// 所有方法都可以并发调用。series 的 key 是渲染好的标签串
/// （例如 `route="r1",status="200"`），保证同一组标签只创建一个计数器。
pub struct Metrics {
    /// counter：metric 名称 → 标签串 → 计数
    counters: RwLock<BTreeMap<String, BTreeMap<String, Arc<AtomicU64>>>>,
    /// gauge：metric 名称 → 标签串 → 当前值
    gauges: RwLock<BTreeMap<String, BTreeMap<String, Arc<AtomicU64>>>>,
    /// histogram：metric 名称 → 标签串 → 累计状态
    histograms: RwLock<BTreeMap<String, BTreeMap<String, Arc<HistogramState>>>>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// 创建空的注册表。
    pub fn new() -> Self {
        Self {
            counters: RwLock::new(BTreeMap::new()),
            gauges: RwLock::new(BTreeMap::new()),
            histograms: RwLock::new(BTreeMap::new()),
        }
    }

    /// 获取进程级全局单例。
    pub fn global() -> &'static Metrics {
        GLOBAL_METRICS.get_or_init(Metrics::new)
    }

    /// counter 自增 1。
    ///
    /// # 参数
    /// - `name`：指标名（建议以 `_total` 结尾）
    /// - `labels`：标签键值对
    pub fn inc_counter(&self, name: &str, labels: &[(&str, &str)]) {
        self.add_counter(name, labels, 1);
    }

    /// counter 增加指定值。
    pub fn add_counter(&self, name: &str, labels: &[(&str, &str)], delta: u64) {
        let key = render_labels(labels);
        // 先尝试读锁走快路径；series 不存在时再升级为写锁插入
        {
            let guard = self.counters.read().unwrap_or_else(|p| p.into_inner());
            if let Some(map) = guard.get(name) {
                if let Some(counter) = map.get(&key) {
                    counter.fetch_add(delta, Ordering::Relaxed);
                    return;
                }
            }
        }

        let mut guard = self.counters.write().unwrap_or_else(|p| p.into_inner());
        let counter = guard
            .entry(name.to_string())
            .or_default()
            .entry(key)
            .or_insert_with(|| Arc::new(AtomicU64::new(0)));
        counter.fetch_add(delta, Ordering::Relaxed);
    }

    /// 设置 gauge 当前值（覆盖语义，不是累加）。
    ///
    /// 用于表达瞬时状态，例如端点健康（0/1）、当前连接数等。
    pub fn set_gauge(&self, name: &str, labels: &[(&str, &str)], value: u64) {
        let key = render_labels(labels);
        {
            let guard = self.gauges.read().unwrap_or_else(|p| p.into_inner());
            if let Some(map) = guard.get(name) {
                if let Some(gauge) = map.get(&key) {
                    gauge.store(value, Ordering::Relaxed);
                    return;
                }
            }
        }

        let mut guard = self.gauges.write().unwrap_or_else(|p| p.into_inner());
        guard
            .entry(name.to_string())
            .or_default()
            .entry(key)
            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
            .store(value, Ordering::Relaxed);
    }

    /// 记录一次直方图观测（单位：毫秒）。
    pub fn observe_ms(&self, name: &str, labels: &[(&str, &str)], value_ms: u64) {
        let key = render_labels(labels);
        let state = {
            let guard = self.histograms.read().unwrap_or_else(|p| p.into_inner());
            guard.get(name).and_then(|map| map.get(&key)).cloned()
        };

        let state = match state {
            Some(state) => state,
            None => {
                let mut guard = self.histograms.write().unwrap_or_else(|p| p.into_inner());
                guard
                    .entry(name.to_string())
                    .or_default()
                    .entry(key)
                    .or_insert_with(|| Arc::new(HistogramState::new()))
                    .clone()
            },
        };

        // 只累加命中的第一个桶：渲染时会做累计求和，因此这里不需要
        // 把后续桶也加一遍。
        for (idx, upper) in DURATION_BUCKETS_MS.iter().enumerate() {
            if value_ms <= *upper {
                if let Some(bucket) = state.buckets.get(idx) {
                    bucket.fetch_add(1, Ordering::Relaxed);
                }
                break;
            }
        }
        state.sum.fetch_add(value_ms, Ordering::Relaxed);
        state.count.fetch_add(1, Ordering::Relaxed);
    }

    /// 根据请求上下文记录一个完整请求的指标。
    ///
    /// 这是 Runtime 在请求结束时（AccessLog 同一时机）调用的唯一入口。
    /// 所有标签值都来自已脱敏的上下文字段，不包含 URL query、凭据等内容。
    pub fn observe_request(&self, ctx: &RequestContext) {
        // 未匹配路由统一归入 "unmatched"，避免空标签导致序列基数失控
        let route = ctx.matched_route.as_ref().map(|r| r.id.as_str()).unwrap_or("unmatched");
        // 状态码缺失（请求被提前终止）时记为 0
        let status = ctx.status_code.map(|s| s.to_string()).unwrap_or_else(|| "0".to_string());

        self.inc_counter("gateway_requests_total", &[("route", route), ("status", &status)]);
        self.observe_ms(
            "gateway_request_duration_milliseconds",
            &[("route", route)],
            ctx.total_duration_ms(),
        );

        // 只有真正选中了上游端点时才记录上游耗时，避免把本地短路
        // 的 0ms 混入上游延迟分布
        if ctx.selected_endpoint.is_some() {
            self.observe_ms(
                "gateway_upstream_duration_milliseconds",
                &[("route", route)],
                ctx.upstream_duration_ms(),
            );
        }

        // 按错误码分类计数：认证失败、限流、上游故障是最关心的三类
        if let Some(code) = ctx.error_code.as_deref() {
            match code {
                "GATEWAY_AUTHENTICATION_FAILED" => {
                    self.inc_counter("gateway_auth_failures_total", &[("route", route)]);
                },
                "GATEWAY_RATE_LIMITED" => {
                    self.inc_counter("gateway_rate_limited_total", &[("route", route)]);
                },
                other if other.starts_with("GATEWAY_UPSTREAM") => {
                    self.inc_counter("gateway_upstream_errors_total", &[("route", route)]);
                },
                _ => {},
            }
        }
    }

    /// 渲染为 Prometheus 文本格式。
    ///
    /// 输出顺序由 `BTreeMap` 保证稳定，便于测试与人工比对。
    pub fn render(&self) -> String {
        let mut out = String::new();

        // ---- counter ----
        let counters = self.counters.read().unwrap_or_else(|p| p.into_inner());
        for (name, series) in counters.iter() {
            // 写 String 不会失败，忽略返回值即可（不需要 unwrap）
            let _ = writeln!(out, "# TYPE {name} counter");
            for (labels, value) in series.iter() {
                let _ = writeln!(out, "{name}{labels} {}", value.load(Ordering::Relaxed));
            }
        }

        // ---- gauge ----
        let gauges = self.gauges.read().unwrap_or_else(|p| p.into_inner());
        for (name, series) in gauges.iter() {
            let _ = writeln!(out, "# TYPE {name} gauge");
            for (labels, value) in series.iter() {
                let _ = writeln!(out, "{name}{labels} {}", value.load(Ordering::Relaxed));
            }
        }

        // ---- histogram ----
        let histograms = self.histograms.read().unwrap_or_else(|p| p.into_inner());
        for (name, series) in histograms.iter() {
            let _ = writeln!(out, "# TYPE {name} histogram");
            for (labels, state) in series.iter() {
                // Prometheus 的 bucket 是累计计数：按桶上界从小到大累加
                let mut cumulative = 0u64;
                for (idx, upper) in DURATION_BUCKETS_MS.iter().enumerate() {
                    if let Some(bucket) = state.buckets.get(idx) {
                        cumulative = cumulative.saturating_add(bucket.load(Ordering::Relaxed));
                    }
                    let bucket_labels = merge_label(labels, "le", &upper.to_string());
                    let _ = writeln!(out, "{name}_bucket{bucket_labels} {cumulative}");
                }

                let count = state.count.load(Ordering::Relaxed);
                // +Inf 桶等于总次数
                let inf_labels = merge_label(labels, "le", "+Inf");
                let _ = writeln!(out, "{name}_bucket{inf_labels} {count}");

                let sum_labels = labels.clone();
                let _ =
                    writeln!(out, "{name}_sum{sum_labels} {}", state.sum.load(Ordering::Relaxed));
                let _ = writeln!(out, "{name}_count{sum_labels} {count}");
            }
        }

        out
    }
}

/// 把标签数组渲染成 `{k="v",k2="v2"}`；没有标签时返回空串。
///
/// 顺序由调用方保证稳定（本模块内所有调用都是固定顺序的字面量）。
fn render_labels(labels: &[(&str, &str)]) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let mut out = String::from("{");
    for (idx, (key, value)) in labels.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(key);
        out.push_str("=\"");
        out.push_str(&escape_label_value(value));
        out.push('"');
    }
    out.push('}');
    out
}

/// 在已有标签串上追加一个 `le` 标签。
///
/// `labels` 可能为空串（无标签 series），此时直接构造一个新标签集。
fn merge_label(labels: &str, key: &str, value: &str) -> String {
    let escaped = escape_label_value(value);
    if labels.is_empty() {
        format!("{{{key}=\"{escaped}\"}}")
    } else {
        // labels 形如 {a="b"}，去掉末尾的 '}' 再追加
        let trimmed = labels.strip_suffix('}').unwrap_or(labels);
        format!("{trimmed},{key}=\"{escaped}\"}}")
    }
}

/// 按 Prometheus 文本协议转义标签值中的特殊字符。
fn escape_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 计数器自增与渲染格式正确
    #[test]
    fn counter_renders_prometheus_format() {
        let metrics = Metrics::new();
        metrics.inc_counter("gateway_requests_total", &[("route", "r1"), ("status", "200")]);
        metrics.inc_counter("gateway_requests_total", &[("route", "r1"), ("status", "200")]);

        let text = metrics.render();
        assert!(text.contains("# TYPE gateway_requests_total counter"));
        assert!(text.contains("gateway_requests_total{route=\"r1\",status=\"200\"} 2"));
    }

    /// 直方图输出累计桶、_sum 与 _count
    #[test]
    fn histogram_renders_cumulative_buckets() {
        let metrics = Metrics::new();
        // 3ms 落在第一个桶（le=5）
        metrics.observe_ms("gateway_request_duration_milliseconds", &[("route", "r1")], 3);
        // 60ms 落在 le=100
        metrics.observe_ms("gateway_request_duration_milliseconds", &[("route", "r1")], 60);

        let text = metrics.render();
        assert!(
            text.contains("gateway_request_duration_milliseconds_bucket{route=\"r1\",le=\"5\"} 1")
        );
        assert!(text
            .contains("gateway_request_duration_milliseconds_bucket{route=\"r1\",le=\"100\"} 2"));
        assert!(text
            .contains("gateway_request_duration_milliseconds_bucket{route=\"r1\",le=\"+Inf\"} 2"));
        assert!(text.contains("gateway_request_duration_milliseconds_sum{route=\"r1\"} 63"));
        assert!(text.contains("gateway_request_duration_milliseconds_count{route=\"r1\"} 2"));
    }

    /// 标签值转义：引号、反斜杠、换行
    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape_label_value("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    /// 无标签的 counter 也能正常渲染
    #[test]
    fn counter_without_labels() {
        let metrics = Metrics::new();
        metrics.inc_counter("gateway_startup_total", &[]);
        assert!(metrics.render().contains("gateway_startup_total 1"));
    }

    /// gauge 是覆盖语义，渲染带 TYPE 声明
    #[test]
    fn gauge_overwrites_and_renders() {
        let metrics = Metrics::new();
        metrics.set_gauge(
            "gateway_endpoint_healthy",
            &[("upstream", "u1"), ("endpoint", "u1-ep-0")],
            0,
        );
        metrics.set_gauge(
            "gateway_endpoint_healthy",
            &[("upstream", "u1"), ("endpoint", "u1-ep-0")],
            1,
        );

        let text = metrics.render();
        assert!(text.contains("# TYPE gateway_endpoint_healthy gauge"));
        assert!(text.contains("gateway_endpoint_healthy{upstream=\"u1\",endpoint=\"u1-ep-0\"} 1"));
        assert!(!text.contains("} 0\n"));
    }
}
