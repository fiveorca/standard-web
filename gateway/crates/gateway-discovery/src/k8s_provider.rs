//! Kubernetes EndpointSlice Provider（Phase 6）。
//!
//! # 数据来源
//!
//! 使用 `discovery.k8s.io/v1` 的 EndpointSlice：
//!
//! ```text
//! GET {api_server}/apis/discovery.k8s.io/v1/namespaces/{ns}/endpointslices
//!     ?labelSelector=kubernetes.io/service-name%3D{service}
//! ```
//!
//! 相比传统 Endpoints 资源，EndpointSlice 是 K8s 官方推荐的扩展方式，
//! 单对象规模受控，更新更细粒度。
//!
//! # 认证
//!
//! 从 ServiceAccount 挂载文件读取 Bearer Token（标准路径
//! `/var/run/secrets/kubernetes.io/serviceaccount/token`），
//! CA 证书从同目录 `ca.crt` 读取，与集群内运行时的行为一致。
//!
//! # 刷新策略
//!
//! `resolve()` 带 TTL 缓存；超过 `refresh_interval` 才真正访问 API。
//! 失败时返回缓存（Last Known Good），并记录警告——
//! 避免控制面抖动导致数据面端点瞬间清空。

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hyper::body::Incoming;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use hyper_rustls::HttpsConnector;
use rustls::RootCertStore;
use tokio::sync::Mutex;

use gateway_core::{
    DiscoveryError, DiscoveryHealth, EndpointConfig, ServiceDiscoveryProvider,
};

/// Kubernetes Provider 配置。
#[derive(Debug, Clone)]
pub struct K8sDiscoveryConfig {
    /// K8s API Server 地址，例如 `https://10.96.0.1:443`
    pub api_server: String,
    /// 命名空间
    pub namespace: String,
    /// Service 名称
    pub service: String,
    /// 端口名过滤（EndpointSlice 上 `ports[].name`）
    pub port_name: Option<String>,
    /// ServiceAccount Token 文件
    pub token_file: String,
    /// CA 证书文件（为 None 时使用系统 webpki roots）
    pub ca_file: Option<String>,
    /// 刷新间隔
    pub refresh_interval: Duration,
    /// 请求超时
    pub request_timeout: Duration,
}

impl K8sDiscoveryConfig {
    /// 从集群内标准环境推导默认配置。
    ///
    /// 环境变量：
    /// - `KUBERNETES_SERVICE_HOST` / `KUBERNETES_SERVICE_PORT`
    pub fn in_cluster(namespace: impl Into<String>, service: impl Into<String>) -> Self {
        let host = std::env::var("KUBERNETES_SERVICE_HOST").unwrap_or_else(|_| "kubernetes.default.svc".to_string());
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_string());
        Self {
            api_server: format!("https://{host}:{port}"),
            namespace: namespace.into(),
            service: service.into(),
            port_name: None,
            token_file: "/var/run/secrets/kubernetes.io/serviceaccount/token".to_string(),
            ca_file: Some("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt".to_string()),
            refresh_interval: Duration::from_secs(15),
            request_timeout: Duration::from_secs(5),
        }
    }
}

/// 一次成功解析的缓存结果。
struct CacheEntry {
    /// 端点列表
    endpoints: Vec<EndpointConfig>,
    /// 上次成功刷新时刻
    refreshed_at: Instant,
}

/// Kubernetes EndpointSlice 服务发现 Provider。
pub struct K8sDiscoveryProvider {
    /// 配置
    config: K8sDiscoveryConfig,
    /// HTTP 客户端（HTTPS + 可选 CA）
    client: Client<HttpsConnector<HttpConnector>, http_body_util::Full<bytes::Bytes>>,
    /// Bearer Token（启动时读取一次；K8s 会在 token 轮换后更新文件，
    /// 这里按需重读）
    cache: Mutex<Option<CacheEntry>>,
}

impl K8sDiscoveryProvider {
    /// 构造 Provider。
    ///
    /// CA 证书加载失败、TLS 初始化失败都会返回错误（启动期暴露问题）。
    pub fn new(config: K8sDiscoveryConfig) -> Result<Self, DiscoveryError> {
        let mut roots = RootCertStore::empty();
        // 系统信任根（访问公网 API Server 或本地开发）
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        if let Some(ca_path) = &config.ca_file {
            let pem = std::fs::read(ca_path).map_err(|e| {
                DiscoveryError::Provider(format!("read k8s ca file {ca_path}: {e}"))
            })?;
            let mut cursor = std::io::Cursor::new(pem);
            for cert in rustls_pemfile::certs(&mut cursor) {
                let der = cert
                    .map_err(|e| DiscoveryError::Provider(format!("parse k8s ca pem: {e}")))?;
                roots.add(der).map_err(|e| {
                    DiscoveryError::Provider(format!("invalid k8s ca certificate: {e}"))
                })?;
            }
        }

        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            // 允许配置为 http://（本地测试/代理场景）
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);

        Ok(Self {
            config,
            client,
            cache: Mutex::new(None),
        })
    }

    /// 读取 Bearer Token。
    fn read_token(&self) -> Result<String, DiscoveryError> {
        let token = std::fs::read_to_string(&self.config.token_file).map_err(|e| {
            DiscoveryError::Provider(format!(
                "read k8s token file {}: {e}",
                self.config.token_file
            ))
        })?;
        Ok(token.trim().to_string())
    }

    /// 向 K8s API 拉取 EndpointSlice 并转换为端点。
    async fn fetch(&self) -> Result<Vec<EndpointConfig>, DiscoveryError> {
        let token = self.read_token()?;
        let url = format!(
            "{}/apis/discovery.k8s.io/v1/namespaces/{}/endpointslices?labelSelector=kubernetes.io%2Fservice-name%3D{}",
            self.config.api_server.trim_end_matches('/'),
            self.config.namespace,
            self.config.service,
        );

        let req = http::Request::builder()
            .method("GET")
            .uri(&url)
            .header("authorization", format!("Bearer {token}"))
            .header("accept", "application/json")
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .map_err(|e| DiscoveryError::Provider(format!("build k8s request: {e}")))?;

        let resp = tokio::time::timeout(self.config.request_timeout, self.client.request(req))
            .await
            .map_err(|_| DiscoveryError::Provider("k8s api request timed out".to_string()))?
            .map_err(|e| DiscoveryError::Provider(format!("k8s api request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(DiscoveryError::Provider(format!(
                "k8s api returned {}",
                resp.status()
            )));
        }

        let body = collect_body(resp.into_body()).await?;
        let text = std::str::from_utf8(&body)
            .map_err(|e| DiscoveryError::Provider(format!("k8s response not utf8: {e}")))?;
        parse_endpointslices(text, self.config.port_name.as_deref())
    }
}

#[async_trait]
impl ServiceDiscoveryProvider for K8sDiscoveryProvider {
    async fn resolve(&self, _upstream_id: &str) -> Result<Vec<EndpointConfig>, DiscoveryError> {
        let now = Instant::now();
        // 先判断缓存是否新鲜
        {
            let guard = self.cache.lock().await;
            if let Some(entry) = guard.as_ref() {
                if now.duration_since(entry.refreshed_at) < self.config.refresh_interval {
                    return Ok(entry.endpoints.clone());
                }
            }
        }

        match self.fetch().await {
            Ok(endpoints) => {
                let mut guard = self.cache.lock().await;
                *guard = Some(CacheEntry {
                    endpoints: endpoints.clone(),
                    refreshed_at: Instant::now(),
                });
                Ok(endpoints)
            },
            Err(err) => {
                // 失败时沿用上一次成功结果（Last Known Good）
                let guard = self.cache.lock().await;
                if let Some(entry) = guard.as_ref() {
                    tracing::warn!(
                        target: "discovery",
                        namespace = %self.config.namespace,
                        service = %self.config.service,
                        error = %err,
                        "k8s endpointslice refresh failed, using last known good"
                    );
                    Ok(entry.endpoints.clone())
                } else {
                    Err(err)
                }
            },
        }
    }

    async fn health(&self) -> DiscoveryHealth {
        let guard = self.cache.lock().await;
        match guard.as_ref() {
            Some(entry)
                if entry.refreshed_at.elapsed() < self.config.refresh_interval * 3 =>
            {
                DiscoveryHealth::Healthy
            },
            Some(_) => DiscoveryHealth::Degraded,
            None => DiscoveryHealth::Unhealthy,
        }
    }
}

/// 收集 HTTP 响应体（K8s API 响应是有限 JSON，可完整缓冲）。
async fn collect_body(mut body: Incoming) -> Result<Vec<u8>, DiscoveryError> {
    use http_body_util::BodyExt;
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| DiscoveryError::Provider(format!("read k8s body: {e}")))?;
        if let Ok(data) = frame.into_data() {
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

/// 解析 EndpointSliceList JSON。
fn parse_endpointslices(
    text: &str,
    port_name: Option<&str>,
    ) -> Result<Vec<EndpointConfig>, DiscoveryError> {
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| DiscoveryError::Provider(format!("parse k8s json: {e}")))?;
    let items = value.get("items").and_then(|v| v.as_array()).map(Vec::as_slice).unwrap_or(&[]);

    let mut endpoints: Vec<EndpointConfig> = Vec::new();
    for item in items {
        // 端口：按 port_name 过滤；未配置时取第一个 TCP 端口
        let ports = item.get("ports").and_then(|v| v.as_array());
        let port = ports.and_then(|ports| {
            ports.iter().find_map(|p| {
                let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let protocol = p.get("protocol").and_then(|v| v.as_str()).unwrap_or("TCP");
                if protocol != "TCP" {
                    return None;
                }
                match port_name {
                    Some(want) if name != want => None,
                    _ => p.get("port").and_then(|v| v.as_u64()).and_then(|n| u16::try_from(n).ok()),
                }
            })
        });

        let Some(port) = port else {
            continue;
        };

        let eps = item.get("endpoints").and_then(|v| v.as_array());
        let Some(eps) = eps else { continue };
        for ep in eps {
            // 只收录 ready=true 的端点（terminating 节点不接收新流量）
            let ready = ep
                .get("conditions")
                .and_then(|c| c.get("ready"))
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if !ready {
                continue;
            }
            let Some(addresses) = ep.get("addresses").and_then(|v| v.as_array()) else {
                continue;
            };
            for addr in addresses {
                if let Some(host) = addr.as_str() {
                    if !host.is_empty() {
                        endpoints.push(EndpointConfig {
                            id: None,
                            host: host.to_string(),
                            port,
                            weight: 1,
                            // EndpointSlice 的 nodeName 可作为区域信息
                            zone: ep
                                .get("nodeName")
                                .and_then(|v| v.as_str())
                                .map(str::to_string),
                            // EndpointSlice 无显式 region 字段
                            region: None,
                        });
                    }
                }
            }
        }
    }

    Ok(endpoints)
}

/// 共享 Provider 的便捷别名（Runtime 中按 upstream 持有）。
pub type SharedK8sProvider = Arc<K8sDiscoveryProvider>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_endpointslice_list() {
        let json = r#"{
            "items": [
                {
                    "endpoints": [
                        {"addresses": ["10.0.0.1"], "conditions": {"ready": true}, "nodeName": "node-a"},
                        {"addresses": ["10.0.0.2"], "conditions": {"ready": false}}
                    ],
                    "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}]
                }
            ]
        }"#;
        let eps = parse_endpointslices(json, Some("http")).expect("parse");
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].host, "10.0.0.1");
        assert_eq!(eps[0].port, 8080);
        assert_eq!(eps[0].zone.as_deref(), Some("node-a"));
    }

    #[test]
    fn port_name_filter() {
        let json = r#"{
            "items": [
                {
                    "endpoints": [{"addresses": ["10.0.0.1"], "conditions": {"ready": true}}],
                    "ports": [{"name": "grpc", "port": 9090, "protocol": "TCP"}]
                }
            ]
        }"#;
        let eps = parse_endpointslices(json, Some("http")).expect("parse");
        assert!(eps.is_empty(), "port name mismatch should skip slice");
    }
}
