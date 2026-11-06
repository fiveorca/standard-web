//! OpenTelemetry 追踪与 W3C Trace Context 传播。
//!
//! 网关作为服务端从下游请求中提取 `traceparent`，为每个请求创建
//! Server Span，并把新的上下文注入到上游请求头中，实现全链路追踪。

use std::time::Duration;

use http::HeaderMap;
use opentelemetry::global::{self, BoxedSpan, BoxedTracer};
use opentelemetry::propagation::{Extractor, TextMapPropagator};
use opentelemetry::trace::{Span, SpanBuilder, SpanKind, Tracer};
use opentelemetry::{Context, KeyValue};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::runtime::Tokio;
use opentelemetry_sdk::trace::{Sampler, TracerProvider};

use crate::config::model::TracingConfig;
use crate::VERSION;

/// 追踪状态。
pub struct TracingState {
    pub enabled: bool,
    tracer: BoxedTracer,
    propagator: TraceContextPropagator,
}

impl TracingState {
    /// 初始化全局 TracerProvider 并返回追踪状态与 provider（用于优雅关闭时 flush）。
    pub fn init(config: &TracingConfig) -> (Self, Option<TracerProvider>) {
        let mut provider = None;

        if config.enabled {
            if let Some(endpoint) = &config.endpoint {
                match build_exporter(endpoint, &config.headers) {
                    Ok(exporter) => {
                        let sampler = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                            config.sample_ratio.clamp(0.0, 1.0),
                        )));
                        let sdk_provider = TracerProvider::builder()
                            .with_batch_exporter(exporter, Tokio)
                            .with_resource(opentelemetry_sdk::Resource::new(vec![
                                KeyValue::new("service.name", config.service_name.clone()),
                                KeyValue::new("service.version", VERSION),
                            ]))
                            .with_sampler(sampler)
                            .build();
                        global::set_tracer_provider(sdk_provider.clone());
                        provider = Some(sdk_provider);
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "failed to initialize OTLP trace exporter; tracing disabled");
                    }
                }
            }
        }

        let tracer = global::tracer(config.service_name.clone());
        (
            Self {
                enabled: config.enabled && provider.is_some(),
                tracer,
                propagator: TraceContextPropagator::new(),
            },
            provider,
        )
    }

    /// 从请求头提取父级追踪上下文。
    pub fn extract(&self, headers: &HeaderMap) -> Context {
        if !self.enabled {
            return Context::new();
        }
        self.propagator.extract(&HeaderExtractor(headers))
    }

    /// 创建服务端 Span。
    pub fn start_server_span(
        &self,
        name: &str,
        parent: &Context,
        attributes: Vec<KeyValue>,
    ) -> Option<BoxedSpan> {
        if !self.enabled {
            return None;
        }
        let builder = SpanBuilder::from_name(name.to_string())
            .with_kind(SpanKind::Server)
            .with_attributes(attributes);
        Some(self.tracer.build_with_context(builder, parent))
    }

    /// 把 Span 上下文注入到上游请求头（W3C traceparent）。
    pub fn inject(&self, span: &BoxedSpan, headers: &mut HeaderMap) {
        let span_context = span.span_context();
        if !span_context.is_valid() {
            return;
        }
        let trace_id = hex::encode(span_context.trace_id().to_bytes());
        let span_id = hex::encode(span_context.span_id().to_bytes());
        let flags = span_context.trace_flags().to_u8();
        let traceparent = format!("00-{trace_id}-{span_id}-{flags:02x}");
        if let Ok(value) = http::HeaderValue::from_str(&traceparent) {
            headers.insert("traceparent", value);
        }
    }

    /// 用于日志与响应头的 trace id。
    pub fn trace_id(span: &Option<BoxedSpan>) -> Option<String> {
        span.as_ref().map(|s| {
            let ctx = s.span_context();
            if ctx.is_valid() {
                hex::encode(ctx.trace_id().to_bytes())
            } else {
                String::new()
            }
        })
    }
}

fn build_exporter(
    endpoint: &str,
    headers: &std::collections::HashMap<String, String>,
) -> Result<opentelemetry_otlp::SpanExporter, String> {
    let mut endpoint = endpoint.trim_end_matches('/').to_string();
    if !endpoint.ends_with("/v1/traces") {
        endpoint.push_str("/v1/traces");
    }
    let mut builder = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .with_timeout(Duration::from_secs(5));
    if !headers.is_empty() {
        builder = builder.with_headers(headers.clone());
    }
    builder
        .build()
        .map_err(|e| format!("failed to build OTLP exporter: {e}"))
}

struct HeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// 关闭并 flush 追踪数据。
pub fn shutdown(provider: Option<TracerProvider>) {
    if let Some(provider) = provider {
        let _ = provider.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_state_produces_no_span() {
        let config = TracingConfig::default();
        let (state, provider) = TracingState::init(&config);
        assert!(!state.enabled);
        assert!(provider.is_none());
        let headers = HeaderMap::new();
        let ctx = state.extract(&headers);
        assert!(state.start_server_span("test", &ctx, vec![]).is_none());
    }
}
