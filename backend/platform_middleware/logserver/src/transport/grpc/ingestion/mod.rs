// ! gRPC LogIngestionService 实现
//
// 消息类型使用 prost 宏手动定义（避免 protoc 构建依赖），
// 与 proto/log/v1/ingestion.proto 保持一致。
//
// 手动实现了 tower::Service + tonic::NamedService，
// 使得 LogIngestionServiceImpl 可以直接用 tonic::Server::builder() 注册。

use crate::application::ingestion::IngestionService;
use crate::common::error::AppError;
use crate::config::GrpcLimits;
use crate::domain::{ExceptionInfo, LogEvent, LogLevel};
use futures::Future;
use prost::Message;
use prost_types::Timestamp;
use std::collections::HashMap;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use tonic::{metadata::MetadataMap, Status};
use tower::Service;
use uuid::Uuid;

// tonic 0.12 中 gRPC 消息用 http_body_util::Full<bytes::Bytes> 作为具体 Body 类型
use bytes::Bytes;

// ========================================
// 手动定义 prost 消息类型 (对齐 ingestion.proto)
// ========================================

#[derive(Clone, PartialEq, Message)]
pub struct LogEventPb {
    #[prost(string, tag = "1")]
    pub schema_version: String,
    #[prost(string, tag = "2")]
    pub event_id: String,
    #[prost(message, optional, tag = "3")]
    pub log_time: Option<Timestamp>,
    #[prost(string, tag = "4")]
    pub level: String,
    #[prost(string, tag = "5")]
    pub service_name: String,
    #[prost(string, tag = "6")]
    pub service_version: String,
    #[prost(string, tag = "7")]
    pub environment: String,
    #[prost(string, tag = "8")]
    pub host_name: String,
    #[prost(string, tag = "9")]
    pub logger: String,
    #[prost(string, tag = "10")]
    pub thread_name: String,
    #[prost(string, tag = "11")]
    pub message: String,
    #[prost(string, tag = "12")]
    pub trace_id: String,
    #[prost(string, tag = "13")]
    pub span_id: String,
    #[prost(string, tag = "14")]
    pub request_id: String,
    #[prost(string, tag = "15")]
    pub tenant_id: String,
    #[prost(message, optional, tag = "16")]
    pub exception: Option<ExceptionInfoPb>,
    #[prost(map = "string, string", tag = "17")]
    pub attributes: HashMap<String, String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ExceptionInfoPb {
    #[prost(string, tag = "1")]
    pub r#type: String,
    #[prost(string, tag = "2")]
    pub message: String,
    #[prost(string, tag = "3")]
    pub stack_trace: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct IngestBatchRequest {
    #[prost(message, repeated, tag = "1")]
    pub events: Vec<LogEventPb>,
}

#[derive(Clone, PartialEq, Message)]
pub struct RejectedEvent {
    #[prost(uint32, tag = "1")]
    pub index: u32,
    #[prost(string, tag = "2")]
    pub event_id: String,
    #[prost(string, tag = "3")]
    pub reason: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct IngestBatchResponse {
    #[prost(string, tag = "1")]
    pub request_id: String,
    #[prost(uint32, tag = "2")]
    pub accepted_count: u32,
    #[prost(uint32, tag = "3")]
    pub rejected_count: u32,
    #[prost(message, repeated, tag = "4")]
    pub rejected_events: Vec<RejectedEvent>,
}

#[derive(Clone, PartialEq, Message)]
pub struct StreamLogRequest {
    #[prost(message, optional, tag = "1")]
    pub event: Option<LogEventPb>,
}

#[derive(Clone, PartialEq, Message)]
pub struct StreamLogResponse {
    #[prost(string, tag = "1")]
    pub request_id: String,
    #[prost(uint32, tag = "2")]
    pub accepted_count: u32,
    #[prost(uint32, tag = "3")]
    pub rejected_count: u32,
}

// ========================================
// 类型转换
// ========================================

impl TryFrom<LogEventPb> for LogEvent {
    type Error = Status;

    fn try_from(p: LogEventPb) -> Result<Self, Self::Error> {
        let event_id: Uuid = Uuid::parse_str(&p.event_id)
            .map_err(|_| Status::invalid_argument(format!("invalid event_id: {}", p.event_id)))?;

        let timestamp = p
            .log_time
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing log_time"))?;

        let t = chrono::DateTime::<chrono::Utc>::from_timestamp(
            timestamp.seconds,
            timestamp.nanos as u32,
        )
        .ok_or_else(|| Status::invalid_argument("invalid log_time"))?;

        let level = LogLevel::from_str(&p.level)
            .ok_or_else(|| Status::invalid_argument(format!("invalid level: {}", p.level)))?;

        let exception = match p.exception {
            Some(ex) if ex.r#type.is_empty() && ex.message.is_empty() && ex.stack_trace.is_empty() => {
                None
            }
            Some(ex) => Some(ExceptionInfo {
                r#type: Some(ex.r#type),
                message: Some(ex.message),
                stack_trace: Some(ex.stack_trace),
            }),
            None => None,
        };

        let attributes: Option<HashMap<String, String>> = if p.attributes.is_empty() {
            None
        } else {
            Some(p.attributes)
        };

        Ok(LogEvent {
            schema_version: if p.schema_version.is_empty() {
                "1.0".to_string()
            } else {
                p.schema_version
            },
            event_id,
            timestamp: t,
            level,
            service_name: p.service_name,
            service_version: Some(p.service_version).filter(|s| !s.is_empty()),
            environment: Some(p.environment).filter(|s| !s.is_empty()),
            host_name: Some(p.host_name).filter(|s| !s.is_empty()),
            logger: Some(p.logger).filter(|s| !s.is_empty()),
            thread_name: Some(p.thread_name).filter(|s| !s.is_empty()),
            message: p.message,
            trace_id: Some(p.trace_id).filter(|s| !s.is_empty()),
            span_id: Some(p.span_id).filter(|s| !s.is_empty()),
            request_id: Some(p.request_id).filter(|s| !s.is_empty()),
            tenant_id: Some(p.tenant_id).filter(|s| !s.is_empty()),
            exception,
            attributes,
            received_at: None,
            ingest_version: None,
        })
    }
}

// ========================================
// 业务实现
// ========================================

pub struct LogIngestionServiceImpl {
    pub service: IngestionService,
    pub limits: GrpcLimits,
}

impl LogIngestionServiceImpl {
    pub fn new(service: IngestionService, limits: GrpcLimits) -> Self {
        Self { service, limits }
    }

    fn extract_tenant(metadata: &MetadataMap) -> String {
        metadata
            .get("x-tenant-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .or_else(|| {
                metadata
                    .get("x-service-name")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "anonymous".into())
    }

    pub async fn ingest_batch(
        &self,
        metadata: MetadataMap,
        body_bytes: Vec<u8>,
    ) -> Result<IngestBatchResponse, Status> {
        let tenant_id = Self::extract_tenant(&metadata);
        let req = IngestBatchRequest::decode(body_bytes.as_ref())
            .map_err(|e| Status::invalid_argument(format!("decode error: {e}")))?;

        if req.events.is_empty() {
            return Err(Status::invalid_argument("events 不能为空"));
        }
        if req.events.len() > self.limits.max_batch_events {
            return Err(Status::resource_exhausted(format!(
                "单次批量最大 {} 条",
                self.limits.max_batch_events
            )));
        }

        let total_bytes: usize = req.events.iter().map(|e| e.encoded_len()).sum();
        if total_bytes > self.limits.max_batch_mb * 1024 * 1024 {
            return Err(Status::resource_exhausted(format!(
                "单次批量超过 {}MB 限制",
                self.limits.max_batch_mb
            )));
        }

        let mut events: Vec<LogEvent> = Vec::with_capacity(req.events.len());
        let mut rejected: Vec<RejectedEvent> = Vec::new();

        for (i, pe) in req.events.into_iter().enumerate() {
            let size = pe.encoded_len();
            if size > self.limits.max_event_kb * 1024 {
                rejected.push(RejectedEvent {
                    index: i as u32,
                    event_id: pe.event_id.clone(),
                    reason: format!("单条日志超过 {}KB 限制", self.limits.max_event_kb),
                });
                continue;
            }
            match LogEvent::try_from(pe) {
                Ok(ev) => events.push(ev),
                Err(s) => {
                    rejected.push(RejectedEvent {
                        index: i as u32,
                        event_id: "".into(),
                        reason: s.to_string(),
                    });
                }
            }
        }

        let request_id = Uuid::new_v4().to_string();

        match self
            .service
            .ingest_batch(request_id.clone(), tenant_id, events)
            .await
        {
            Ok(resp) => {
                let mut all_rejected = rejected;
                for r in &resp.rejected {
                    all_rejected.push(RejectedEvent {
                        index: r.index as u32,
                        event_id: "".into(),
                        reason: r.reason.clone().unwrap_or_default(),
                    });
                }

                crate::observability::GRPC_INGEST_BATCH_TOTAL.inc();
                crate::observability::GRPC_ACCEPTED_TOTAL.inc_by(resp.accepted_count as f64);
                crate::observability::GRPC_REJECTED_TOTAL.inc_by(resp.rejected_count as f64);

                Ok(IngestBatchResponse {
                    request_id: resp.request_id,
                    accepted_count: resp.accepted_count,
                    rejected_count: resp.rejected_count,
                    rejected_events: all_rejected,
                })
            }
            Err(AppError::Kafka(msg)) => Err(Status::unavailable(msg)),
            Err(AppError::Validation(msg)) => Err(Status::invalid_argument(msg)),
            Err(other) => Err(Status::internal(other.to_string())),
        }
    }

    pub async fn stream_logs(
        &self,
        metadata: MetadataMap,
        all_frames: Vec<Vec<u8>>,
    ) -> Result<StreamLogResponse, Status> {
        let tenant_id = Self::extract_tenant(&metadata);

        let mut events = Vec::with_capacity(256);
        let mut rejected_count = 0u32;
        let mut accepted_count = 0u32;

        for frame_bytes in all_frames {
            let pb_event = match StreamLogRequest::decode(frame_bytes.as_ref()) {
                Ok(r) => r.event,
                Err(_) => {
                    rejected_count += 1;
                    continue;
                }
            };
            let pb_event = match pb_event {
                Some(e) => e,
                None => {
                    rejected_count += 1;
                    continue;
                }
            };
            match LogEvent::try_from(pb_event) {
                Ok(ev) => events.push(ev),
                Err(_) => rejected_count += 1,
            }

            if events.len() >= self.limits.max_batch_events {
                let request_id = Uuid::new_v4().to_string();
                match self
                    .service
                    .ingest_batch(request_id, tenant_id.clone(), std::mem::take(&mut events))
                    .await
                {
                    Ok(resp) => {
                        accepted_count += resp.accepted_count;
                        rejected_count += resp.rejected_count;
                    }
                    Err(AppError::Kafka(_)) => return Err(Status::unavailable("Kafka 暂不可用")),
                    Err(other) => return Err(Status::internal(other.to_string())),
                }
            }
        }

        if !events.is_empty() {
            let request_id = Uuid::new_v4().to_string();
            match self
                .service
                .ingest_batch(request_id, tenant_id.clone(), events)
                .await
            {
                Ok(resp) => {
                    accepted_count += resp.accepted_count;
                    rejected_count += resp.rejected_count;
                }
                Err(other) => return Err(Status::internal(other.to_string())),
            }
        }

        crate::observability::GRPC_INGEST_BATCH_TOTAL.inc();
        crate::observability::GRPC_ACCEPTED_TOTAL.inc_by(accepted_count as f64);
        crate::observability::GRPC_REJECTED_TOTAL.inc_by(rejected_count as f64);

        Ok(StreamLogResponse {
            request_id: Uuid::new_v4().to_string(),
            accepted_count,
            rejected_count,
        })
    }
}

// ========================================
// 手动实现 tonic::NamedService + tower::Service
// ========================================

const INGEST_BATCH_PATH: &str = "/log.v1.LogIngestionService/IngestBatch";
const STREAM_LOGS_PATH: &str = "/log.v1.LogIngestionService/StreamLogs";

/// tonic 0.12 内部用的 BoxBody 类型
type BoxBody = http_body_util::combinators::UnsyncBoxBody<Bytes, Status>;

#[derive(Clone)]
pub struct LogIngestionServiceSvc {
    inner: Arc<LogIngestionServiceImpl>,
}

impl LogIngestionServiceSvc {
    pub fn new(inner: Arc<LogIngestionServiceImpl>) -> Self {
        Self { inner }
    }
}

impl tonic::server::NamedService for LogIngestionServiceSvc {
    const NAME: &'static str = "log.v1.LogIngestionService";
}

impl Service<http::Request<BoxBody>> for LogIngestionServiceSvc {
    type Response = http::Response<BoxBody>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<BoxBody>) -> Self::Future {
        let inner = self.inner.clone();
        let path = req.uri().path().to_string();
        let metadata = extract_metadata(&req);

        Box::pin(async move {
            match path.as_str() {
                INGEST_BATCH_PATH => {
                    let bytes = match box_body_collect(req.into_body()).await {
                        Ok(b) => b,
                        Err(e) => return Ok(grpc_error_response(Status::internal(e))),
                    };
                    match inner.ingest_batch(metadata, bytes).await {
                        Ok(resp) => Ok(grpc_ok_response(resp.encode_to_vec())),
                        Err(status) => Ok(grpc_error_response(status)),
                    }
                }
                STREAM_LOGS_PATH => {
                    let frames = match box_body_stream_collect(req.into_body()).await {
                        Ok(f) => f,
                        Err(e) => return Ok(grpc_error_response(Status::internal(e))),
                    };
                    match inner.stream_logs(metadata, frames).await {
                        Ok(resp) => Ok(grpc_ok_response(resp.encode_to_vec())),
                        Err(status) => Ok(grpc_error_response(status)),
                    }
                }
                _ => Ok(grpc_error_response(Status::unimplemented(format!(
                    "unknown RPC path: {path}"
                )))),
            }
        })
    }
}

// ========================================
// HTTP / gRPC 辅助函数
// ========================================

fn extract_metadata(req: &http::Request<BoxBody>) -> MetadataMap {
    let mut map = MetadataMap::new();
    for (k, v) in req.headers() {
        if let Ok(name) = tonic::metadata::MetadataKey::from_bytes(k.as_str().as_bytes()) {
            let value = tonic::metadata::MetadataValue::<tonic::metadata::Ascii>::try_from(v.as_bytes());
            match value {
                Ok(val) => {
                    map.insert(name, val);
                }
                Err(_) => { /* binary header, skip */ }
            }
        }
    }
    map
}

async fn box_body_collect(body: BoxBody) -> Result<Vec<u8>, String> {
    use http_body_util::BodyExt;
    let collected = body.collect().await.map_err(|e| format!("body collect error: {e}"))?;
    Ok(collected.to_bytes().to_vec())
}

async fn box_body_stream_collect(body: BoxBody) -> Result<Vec<Vec<u8>>, String> {
    use http_body_util::BodyExt;
    let mut frames = Vec::new();
    let mut body = body;
    while let Some(frame_res) = body.frame().await {
        match frame_res {
            Ok(frame) => {
                if let Ok(bytes) = frame.into_data() {
                    frames.push(bytes.to_vec());
                }
            }
            Err(e) => {
                tracing::warn!(?e, "gRPC stream frame error");
                break;
            }
        }
    }
    Ok(frames)
}

fn grpc_ok_response(body: Vec<u8>) -> http::Response<BoxBody> {
    use http_body_util::BodyExt;
    let full = http_body_util::Full::new(Bytes::from(body));
    let body: BoxBody = full
        .map_err(|never| match never {})
        .boxed_unsync();
    http::Response::builder()
        .status(http::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", "0")
        .body(body)
        .unwrap()
}

fn grpc_error_response(status: Status) -> http::Response<BoxBody> {
    use http_body_util::BodyExt;
    let code = status.code() as i32;
    let msg = percent_encode(status.message());
    let full = http_body_util::Full::new(Bytes::new());
    let body: BoxBody = full
        .map_err(|never| match never {})
        .boxed_unsync();
    http::Response::builder()
        .status(http::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", format!("{code}"))
        .header("grpc-message", msg)
        .body(body)
        .unwrap()
}

fn percent_encode(s: &str) -> String {
    // 简单转义: HTTP header value 不能包含换行等
    s.replace('\n', " ")
        .replace('\r', " ")
        .replace('\t', " ")
}

// ========================================
// 导出
// ========================================

/// 创建可被 tonic::Server::builder().add_service() 注册的 service
pub fn into_tonic_service(impl_: Arc<LogIngestionServiceImpl>) -> LogIngestionServiceSvc {
    LogIngestionServiceSvc::new(impl_)
}
