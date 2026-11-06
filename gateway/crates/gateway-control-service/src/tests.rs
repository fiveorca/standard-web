//! 控制面服务测试。
//!
//! 使用内存仓储，覆盖：
//!   1. 发布成功（校验/版本/checksum/审计/实例应用记录）
//!   2. 校验失败不产生版本
//!   3. 回滚 = 新版本 + 历史内容
//!   4. 乐观锁与 payload 结构校验

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use gateway_config::{CompiledSnapshot, ResourceBundle, SCHEMA_VERSION};
use gateway_storage::{MemoryRepository, ResourceDraft, ResourceKind, ResourceUpdate};
use serde_json::{json, Value};

use crate::applier::SnapshotApplier;
use crate::error::ControlError;
use crate::service::ConfigService;

// ---------------------------------------------------------------------------
// 测试替身：记录应用次数，可模拟失败
// ---------------------------------------------------------------------------

struct RecordingApplier {
    applied: AtomicU64,
    fail: AtomicBool,
}

impl RecordingApplier {
    fn new(fail: bool) -> Self {
        Self {
            applied: AtomicU64::new(0),
            fail: AtomicBool::new(fail),
        }
    }

    fn applied_version(&self) -> u64 {
        self.applied.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl SnapshotApplier for RecordingApplier {
    async fn apply(&self, snapshot: &CompiledSnapshot) -> Result<u64, String> {
        if self.fail.load(Ordering::SeqCst) {
            return Err("simulated apply failure".to_string());
        }
        self.applied.store(snapshot.config_version, Ordering::SeqCst);
        Ok(snapshot.config_version)
    }
}

// ---------------------------------------------------------------------------
// 测试数据构造
// ---------------------------------------------------------------------------

fn upstream_payload(id: &str) -> Value {
    json!({
        "id": id,
        "algorithm": "round_robin",
        "endpoints": [{ "host": "127.0.0.1", "port": 9000 }]
    })
}

fn service_payload(id: &str, upstream_id: &str) -> Value {
    json!({ "id": id, "upstream_id": upstream_id })
}

fn route_payload(id: &str, service_id: &str, path: &str) -> Value {
    json!({
        "id": id,
        "path_type": "prefix",
        "path_value": path,
        "service_id": service_id
    })
}

fn draft(id: &str, payload: Value) -> ResourceDraft {
    ResourceDraft {
        id: id.to_string(),
        name: Some(id.to_string()),
        enabled: true,
        payload,
    }
}

fn service() -> ConfigService {
    ConfigService::new(Arc::new(MemoryRepository::new()))
}

/// 创建一条最小可用配置：upstream → service → route。
async fn seed_valid_config(svc: &ConfigService) {
    svc.create_resource(ResourceKind::Upstream, draft("up-1", upstream_payload("up-1")), "alice")
        .await
        .expect("create upstream");

    svc.create_resource(
        ResourceKind::Service,
        draft("svc-1", service_payload("svc-1", "up-1")),
        "alice",
    )
    .await
    .expect("create service");

    svc.create_resource(
        ResourceKind::Route,
        draft("r-1", route_payload("r-1", "svc-1", "/api")),
        "alice",
    )
    .await
    .expect("create route");
}

#[tokio::test]
async fn publish_applies_snapshot_and_records_audit() {
    let applier = Arc::new(RecordingApplier::new(false));
    let svc = ConfigService::with_applier(
        Arc::new(MemoryRepository::new()),
        applier.clone(),
        "gateway-test",
    );
    seed_valid_config(&svc).await;

    // dry-run 校验
    let report = svc.validate().await.expect("validate");
    assert!(report.valid);
    assert_eq!(report.resource_counts.routes, 1);
    assert!(report.checksum.is_some());

    // 发布
    let outcome = svc.publish("alice", Some("initial".into())).await.expect("publish");
    assert_eq!(outcome.version, 1);
    assert!(outcome.applied);
    assert_eq!(outcome.checksum.len(), 64);
    assert_eq!(applier.applied_version(), 1);

    // 实例应用记录
    let records = svc.list_publish_records(None, 10, 0).await.expect("records");
    assert_eq!(records.items.len(), 1);
    assert_eq!(records.items[0].version, 1);

    // 审计：3 次 create + 1 次 publish
    let audits = svc.list_audit_logs(None, 10, 0).await.expect("audit");
    assert_eq!(audits.items.len(), 4);
    assert_eq!(audits.items[0].action, "publish");
    assert_eq!(audits.items[0].version, Some(1));
}

#[tokio::test]
async fn invalid_reference_does_not_create_version() {
    let svc = service();
    svc.create_resource(
        ResourceKind::Route,
        draft("r-1", route_payload("r-1", "missing-svc", "/api")),
        "alice",
    )
    .await
    .expect("route shape is valid");

    let err = svc.publish("alice", None).await.expect_err("must fail");
    assert!(matches!(err, ControlError::Validation { .. }));
    assert!(svc.latest_version().await.expect("latest").is_none());
}

#[tokio::test]
async fn rollback_replays_history_as_new_version() {
    let svc = service();
    seed_valid_config(&svc).await;
    let v1 = svc.publish("alice", None).await.expect("publish v1");
    assert_eq!(v1.version, 1);

    // 修改路由路径后发布 v2
    let updated = svc
        .update_resource(
            ResourceKind::Route,
            "r-1",
            ResourceUpdate {
                name: None,
                enabled: None,
                payload: Some(route_payload("r-1", "svc-1", "/v2")),
                expected_version: Some(1),
            },
            "alice",
        )
        .await
        .expect("update");
    assert_eq!(updated.version, 2);

    let v2 = svc.publish("bob", None).await.expect("publish v2");
    assert_eq!(v2.version, 2);

    // 回滚到 v1 → 产生 v3，且内容是 v1 的路径
    let v3 = svc.rollback(1, "bob", None).await.expect("rollback");
    assert_eq!(v3.version, 3);
    assert_eq!(v3.note.as_deref(), Some("rollback to v1"), "回滚备注应自动填充");

    let record = svc.get_version(3).await.expect("version 3");
    let bundle: ResourceBundle = serde_json::from_value(record.snapshot).expect("bundle");
    assert_eq!(bundle.routes[0].path_value, "/api");
    assert_eq!(record.schema_version, SCHEMA_VERSION);
}

#[tokio::test]
async fn apply_failure_is_recorded_but_version_kept() {
    let applier = Arc::new(RecordingApplier::new(true));
    let svc =
        ConfigService::with_applier(Arc::new(MemoryRepository::new()), applier, "gateway-test");
    seed_valid_config(&svc).await;

    let outcome = svc.publish("alice", None).await.expect("publish");
    assert!(!outcome.applied);
    assert_eq!(outcome.apply_error.as_deref(), Some("simulated apply failure"));

    // 版本仍然保存（可用于排查/回滚）
    assert!(svc.latest_version().await.expect("latest").is_some());

    let records = svc.list_publish_records(None, 10, 0).await.expect("records");
    assert_eq!(records.items.len(), 1);
    assert_eq!(records.items[0].status, gateway_storage::PublishStatus::Failed);
}

#[tokio::test]
async fn optimistic_lock_conflict_is_mapped() {
    let svc = service();
    seed_valid_config(&svc).await;

    let err = svc
        .update_resource(
            ResourceKind::Route,
            "r-1",
            ResourceUpdate {
                name: None,
                enabled: Some(false),
                payload: None,
                expected_version: Some(99),
            },
            "alice",
        )
        .await
        .expect_err("stale version");
    assert!(matches!(err, ControlError::VersionConflict { .. }));
}

#[tokio::test]
async fn payload_id_must_match_resource_id() {
    let svc = service();
    let err = svc
        .create_resource(
            ResourceKind::Route,
            draft("r-1", route_payload("other", "svc-1", "/api")),
            "alice",
        )
        .await
        .expect_err("id mismatch");
    assert!(matches!(err, ControlError::InvalidPayload { .. }));
}

#[tokio::test]
async fn disabled_resource_is_applied_on_publish() {
    let svc = service();
    seed_valid_config(&svc).await;
    svc.publish("alice", None).await.expect("publish");

    // 禁用路由后重新发布，快照中的 route.enabled 必须为 false
    svc.update_resource(
        ResourceKind::Route,
        "r-1",
        ResourceUpdate {
            name: None,
            enabled: Some(false),
            payload: None,
            expected_version: Some(1),
        },
        "alice",
    )
    .await
    .expect("disable");

    let outcome = svc.publish("alice", None).await.expect("publish");
    let record = svc.get_version(outcome.version).await.expect("version");
    let bundle: ResourceBundle = serde_json::from_value(record.snapshot).expect("bundle");
    assert!(!bundle.routes[0].enabled);
    assert_eq!(bundle.routes[0].path_value, "/api");
}

// ---------------------------------------------------------------------------
// 证书资源：真实 PEM 校验 + 私钥脱敏 + 读改写恢复
// ---------------------------------------------------------------------------

/// 生成测试用自签名证书，返回 `(cert_pem, key_pem)`。
fn test_certificate(domain: &str) -> (String, String) {
    let generated = rcgen::generate_simple_self_signed(vec![domain.to_string()])
        .expect("generate self-signed certificate");
    (generated.cert.pem(), generated.key_pair.serialize_pem())
}

fn certificate_payload(id: &str, cert_pem: &str, key_pem: &str) -> Value {
    json!({
        "id": id,
        "cert_pem": cert_pem,
        "key_pem": key_pem,
        "domains": ["api.example.com"]
    })
}

#[tokio::test]
async fn certificate_private_key_is_redacted_in_reads() {
    let (cert_pem, key_pem) = test_certificate("api.example.com");
    let svc = service();
    svc.create_resource(
        ResourceKind::Certificate,
        draft("cert-1", certificate_payload("cert-1", &cert_pem, &key_pem)),
        "alice",
    )
    .await
    .expect("create certificate");

    // 读取时私钥必须脱敏，证书链保持可见
    let fetched = svc.get_resource(ResourceKind::Certificate, "cert-1").await.expect("get");
    assert_eq!(fetched.payload["key_pem"], "[redacted]");
    assert_eq!(fetched.payload["cert_pem"], cert_pem);

    // 列表同样脱敏
    let page = svc.list_resources(ResourceKind::Certificate, 10, 0).await.expect("list");
    assert_eq!(page.items[0].payload["key_pem"], "[redacted]");
}

#[tokio::test]
async fn update_with_redacted_key_keeps_stored_private_key() {
    let (cert_pem, key_pem) = test_certificate("api.example.com");
    let svc = service();
    svc.create_resource(
        ResourceKind::Certificate,
        draft("cert-1", certificate_payload("cert-1", &cert_pem, &key_pem)),
        "alice",
    )
    .await
    .expect("create certificate");

    // 模拟 GET → 修改其他字段 → PUT：私钥是脱敏占位符
    let mut payload = certificate_payload("cert-1", &cert_pem, "[redacted]");
    payload["domains"] = json!(["api.example.com", "www.example.com"]);
    svc.update_resource(
        ResourceKind::Certificate,
        "cert-1",
        ResourceUpdate {
            name: Some("renamed".into()),
            enabled: None,
            payload: Some(payload),
            expected_version: Some(1),
        },
        "alice",
    )
    .await
    .expect("update");

    // 仓储中的真实私钥必须保持不变
    let stored = svc
        .repository()
        .get_resource(ResourceKind::Certificate, "cert-1")
        .await
        .expect("repo get")
        .expect("cert exists");
    assert_eq!(stored.payload["key_pem"], key_pem);
    assert_eq!(stored.payload["domains"].as_array().unwrap().len(), 2);
    assert_eq!(stored.name.as_deref(), Some("renamed"));
}

#[tokio::test]
async fn certificate_with_mismatched_key_is_rejected() {
    let (cert_pem, _) = test_certificate("api.example.com");
    let (_, other_key) = test_certificate("other.example.com");
    let svc = service();

    let err = svc
        .create_resource(
            ResourceKind::Certificate,
            draft("cert-1", certificate_payload("cert-1", &cert_pem, &other_key)),
            "alice",
        )
        .await
        .expect_err("mismatched key must be rejected");
    assert!(matches!(err, ControlError::InvalidPayload { .. }));
}
