//! TLS 运行时组装：配置 / 配置快照 / 文件证书 → rustls 证书集合。
//!
//! 证书来源优先级：
//!   1. `server.http.tls.certificate_id` 指定的证书作为默认证书；
//!   2. 配置快照中的证书（控制面发布）按 domains 参与 SNI；
//!   3. `cert_file` / `key_file` 文件证书，支持定时热重载；
//!   4. 启动引导阶段使用 YAML 中的 `certificates` 列表。
//!
//! 快照应用采用两阶段提交：`prepare_snapshot()` 只解析校验，控制面/配置
//! 快照真正应用成功后再 `commit_snapshot()`，避免坏证书导致运行时状态
//! 与配置版本不一致。
//!
//! 控制面引导模式（`control_plane.enabled = true`）：启动时不要求本地存在
//! 任何证书，HTTPS 端口照常监听但握手会失败，直到控制面首个带证书的快照
//! 提交后自动激活；独立部署模式保持严格校验，无证书直接拒绝启动。

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use gateway_config::GatewayConfig;
use gateway_core::CertificateConfig;
use gateway_network::tls::{self, LoadedCertificate, PreparedCertificates, TlsRuntime};

/// 文件证书在 SNI 集合中的固定 ID。
const FILE_CERTIFICATE_ID: &str = "__file__";

/// 运行时 TLS 状态。
pub struct RuntimeTls {
    runtime: Arc<TlsRuntime>,
    default_id: Option<String>,
    /// 当前快照中的证书（已解析）
    snapshot_certs: RwLock<Vec<LoadedCertificate>>,
    /// 文件证书（已解析）
    file_cert: RwLock<Option<LoadedCertificate>>,
    /// 文件路径，用于热重载
    file_paths: Option<(PathBuf, PathBuf)>,
    /// 上次加载的文件指纹（mtime + len），避免无变化时重复解析
    file_fingerprint: RwLock<Option<(SystemTime, u64, SystemTime, u64)>>,
    /// 热重载轮询间隔
    reload_interval: Duration,
    /// 控制面引导模式：允许空证书集合（等待控制面下发）
    allow_empty_bootstrap: bool,
}

/// `prepare_snapshot` 的产物，等待 `commit_snapshot` 提交。
pub struct PreparedTls {
    snapshot_certs: Vec<LoadedCertificate>,
    prepared: PreparedCertificates,
}

impl RuntimeTls {
    /// 根据配置构建 TLS 运行时；未启用 HTTPS 时返回 `None`。
    pub fn build(cfg: &GatewayConfig) -> Result<Option<Arc<Self>>, String> {
        let listener = &cfg.server.http.tls;
        if !listener.enabled {
            return Ok(None);
        }

        let client_ca_pem = match &listener.client_ca_file {
            Some(path) => Some(read_file(path, "client CA")?),
            None => None,
        };

        let runtime = Arc::new(TlsRuntime::new(client_ca_pem.as_deref())?);

        let file_cert = load_file_certificate(
            listener.cert_file.as_deref(),
            listener.key_file.as_deref(),
            &listener.domains,
        )?;

        let snapshot_certs = parse_config_certificates(&cfg.certificates)?;
        let mut initial_certs = snapshot_certs.clone();
        if let Some(file_cert) = &file_cert {
            initial_certs.push(file_cert.clone());
        }

        // 控制面引导模式允许零证书启动：端口先监听、握手先失败，
        // 等控制面下发首个带证书的快照后自动激活；独立部署保持严格。
        let allow_empty_bootstrap = cfg.control_plane.enabled;
        if initial_certs.is_empty() {
            if allow_empty_bootstrap {
                tracing::warn!(
                    target: "tls",
                    "tls enabled without any local certificate; \
                     HTTPS handshakes will fail until the control plane publishes certificates"
                );
            } else {
                return Err(
                    "tls enabled but no certificate source: configure certificate_id or cert_file/key_file"
                        .to_string(),
                );
            }
        } else {
            let prepared = TlsRuntime::prepare(initial_certs, listener.certificate_id.as_deref())?;
            runtime.commit(prepared);
        }

        let fingerprint = file_fingerprint(
            listener.cert_file.as_deref().map(Path::new),
            listener.key_file.as_deref().map(Path::new),
        )?;

        Ok(Some(Arc::new(Self {
            runtime,
            default_id: listener.certificate_id.clone(),
            snapshot_certs: RwLock::new(snapshot_certs),
            file_cert: RwLock::new(file_cert),
            file_paths: match (listener.cert_file.as_deref(), listener.key_file.as_deref()) {
                (Some(cert), Some(key)) => Some((PathBuf::from(cert), PathBuf::from(key))),
                _ => None,
            },
            file_fingerprint: RwLock::new(fingerprint),
            reload_interval: Duration::from_secs(listener.reload_interval_secs.max(1)),
            allow_empty_bootstrap,
        })))
    }

    /// 当前 acceptor 使用的 rustls 运行时。
    pub fn runtime(&self) -> Arc<TlsRuntime> {
        self.runtime.clone()
    }

    /// 文件证书热重载轮询间隔。
    pub fn reload_interval(&self) -> Duration {
        self.reload_interval
    }

    /// 是否配置了文件证书（决定是否启动热重载任务）。
    pub fn has_file_certificate(&self) -> bool {
        self.file_paths.is_some()
    }

    /// 解析并校验快照证书，不修改运行中状态。
    pub fn prepare_snapshot(&self, certs: &[CertificateConfig]) -> Result<PreparedTls, String> {
        let snapshot_certs = parse_config_certificates(certs)?;
        let mut all = snapshot_certs.clone();
        if let Ok(file) = self.file_cert.read() {
            if let Some(file) = file.as_ref() {
                all.push(file.clone());
            }
        }
        // 控制面引导模式下快照可以不含证书（等待后续下发），
        // 独立部署模式仍然要求至少一张可用证书。
        let prepared = if self.allow_empty_bootstrap {
            TlsRuntime::prepare_allow_empty(all, self.default_id.as_deref())?
        } else {
            TlsRuntime::prepare(all, self.default_id.as_deref())?
        };
        Ok(PreparedTls {
            snapshot_certs,
            prepared,
        })
    }

    /// 提交快照证书（在快照版本校验通过之后调用）。
    pub fn commit_snapshot(&self, prepared: PreparedTls) {
        if let Ok(mut guard) = self.snapshot_certs.write() {
            *guard = prepared.snapshot_certs;
        }
        self.runtime.commit(prepared.prepared);
    }

    /// 检查文件证书是否变化；变化则重新加载并热替换。
    ///
    /// 返回 `Ok(true)` 表示证书已更新。
    pub fn reload_files_if_changed(&self) -> Result<bool, String> {
        let Some((cert_path, key_path)) = &self.file_paths else {
            return Ok(false);
        };

        let current = file_fingerprint(Some(cert_path.as_path()), Some(key_path.as_path()))?;
        let unchanged = match (self.file_fingerprint.read(), current) {
            (Ok(guard), Some(current)) => guard.is_some_and(|old| old == current),
            _ => false,
        };
        if unchanged {
            return Ok(false);
        }

        let file_cert = tls::certificate(
            FILE_CERTIFICATE_ID,
            self.file_domains(),
            tls::load_from_files(cert_path, key_path)?,
        );

        let snapshot_certs =
            self.snapshot_certs.read().map(|guard| guard.clone()).unwrap_or_default();
        let mut all = snapshot_certs;
        all.push(file_cert.clone());

        let prepared = TlsRuntime::prepare(all, self.default_id.as_deref())?;
        self.runtime.commit(prepared);
        if let Ok(mut guard) = self.file_cert.write() {
            *guard = Some(file_cert);
        }
        if let Ok(mut guard) = self.file_fingerprint.write() {
            *guard = current;
        }
        tracing::info!(target: "tls", "file certificate reloaded");
        Ok(true)
    }

    fn file_domains(&self) -> Vec<String> {
        self.file_cert
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().map(|c| c.domains.clone()))
            .unwrap_or_default()
    }
}

fn parse_config_certificates(
    certs: &[CertificateConfig],
) -> Result<Vec<LoadedCertificate>, String> {
    let mut loaded = Vec::new();
    for cert in certs.iter().filter(|c| c.enabled) {
        let key = tls::load_from_pem(&cert.cert_pem, &cert.key_pem)
            .map_err(|e| format!("certificate '{}': {e}", cert.id))?;
        loaded.push(tls::certificate(cert.id.clone(), cert.domains.clone(), key));
    }
    Ok(loaded)
}

fn load_file_certificate(
    cert_file: Option<&str>,
    key_file: Option<&str>,
    domains: &[String],
) -> Result<Option<LoadedCertificate>, String> {
    match (cert_file, key_file) {
        (Some(cert), Some(key)) => Ok(Some(tls::certificate(
            FILE_CERTIFICATE_ID,
            domains.to_vec(),
            tls::load_from_files(Path::new(cert), Path::new(key))?,
        ))),
        (None, None) => Ok(None),
        _ => Err("cert_file and key_file must be configured together".to_string()),
    }
}

fn read_file(path: &str, purpose: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("failed to read {purpose} file {path}: {e}"))
}

fn file_fingerprint(
    cert_file: Option<&Path>,
    key_file: Option<&Path>,
) -> Result<Option<(SystemTime, u64, SystemTime, u64)>, String> {
    let (Some(cert), Some(key)) = (cert_file, key_file) else {
        return Ok(None);
    };
    let cert_meta = std::fs::metadata(cert)
        .map_err(|e| format!("failed to stat certificate file {}: {e}", cert.display()))?;
    let key_meta = std::fs::metadata(key)
        .map_err(|e| format!("failed to stat key file {}: {e}", key.display()))?;
    let cert_mtime = cert_meta
        .modified()
        .map_err(|e| format!("failed to read certificate mtime: {e}"))?;
    let key_mtime = key_meta.modified().map_err(|e| format!("failed to read key mtime: {e}"))?;
    Ok(Some((cert_mtime, cert_meta.len(), key_mtime, key_meta.len())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_config::loader::load_from_str;

    fn test_certificate(domain: &str) -> (String, String) {
        let generated = rcgen::generate_simple_self_signed(vec![domain.to_string()])
            .expect("generate certificate");
        (generated.cert.pem(), generated.key_pair.serialize_pem())
    }

    fn certificate_config(id: &str, domain: &str) -> CertificateConfig {
        let (cert_pem, key_pem) = test_certificate(domain);
        CertificateConfig {
            id: id.to_string(),
            name: None,
            enabled: true,
            cert_pem,
            key_pem,
            domains: vec![domain.to_string()],
            not_after: None,
        }
    }

    /// 控制面引导模式：本地零证书也能构建 TLS 运行时
    #[test]
    fn control_plane_mode_builds_tls_without_local_certificate() {
        let yaml = r#"
gateway: { id: g }
server:
  http:
    port: 8443
    tls: { enabled: true, certificate_id: "api-cert" }
control_plane:
  enabled: true
  endpoint: "http://localhost:8092"
"#;
        let cfg = load_from_str(yaml).expect("parse config");
        let tls = RuntimeTls::build(&cfg).expect("build must succeed").expect("tls enabled");
        // 尚无证书：握手会失败，等待控制面下发
        assert!(!tls.runtime().has_certificate());
    }

    /// 独立部署模式：本地零证书直接拒绝启动
    #[test]
    fn standalone_mode_rejects_tls_without_certificate() {
        let yaml = r#"
gateway: { id: g }
server:
  http:
    port: 8443
    tls: { enabled: true }
"#;
        let cfg = load_from_str(yaml).expect("parse config");
        let err = RuntimeTls::build(&cfg).err().expect("must fail");
        assert!(err.contains("no certificate source"), "unexpected error: {err}");
    }

    /// 控制面下发证书的快照提交后，HTTPS 立即激活
    #[test]
    fn snapshot_with_certificate_activates_tls() {
        let yaml = r#"
gateway: { id: g }
server:
  http:
    port: 8443
    tls: { enabled: true, certificate_id: "api-cert" }
control_plane:
  enabled: true
"#;
        let cfg = load_from_str(yaml).expect("parse config");
        let tls = RuntimeTls::build(&cfg).expect("build").expect("tls enabled");
        assert!(!tls.runtime().has_certificate());

        // 空快照也允许提交（证书等待后续版本下发）
        let empty = tls.prepare_snapshot(&[]).expect("empty snapshot allowed");
        tls.commit_snapshot(empty);
        assert!(!tls.runtime().has_certificate());

        // 带证书的快照提交后立即生效，且 certificate_id 成为默认证书
        let certs = vec![certificate_config("api-cert", "api.example.com")];
        let prepared = tls.prepare_snapshot(&certs).expect("prepare snapshot");
        tls.commit_snapshot(prepared);
        assert!(tls.runtime().has_certificate());
    }

    /// 坏证书的快照在 prepare 阶段被拒绝，现有证书不受影响
    #[test]
    fn invalid_snapshot_certificate_is_rejected_without_touching_state() {
        let (cert_pem, key_pem) = test_certificate("api.example.com");
        let yaml = format!(
            r#"
gateway: {{ id: g }}
server:
  http:
    port: 8443
    tls: {{ enabled: true }}
control_plane:
  enabled: true
certificates:
  - id: api-cert
    enabled: true
    domains: ["api.example.com"]
    cert_pem: |
{cert}
    key_pem: |
{key}
"#,
            cert = cert_pem.lines().map(|l| format!("      {l}")).collect::<Vec<_>>().join("\n"),
            key = key_pem.lines().map(|l| format!("      {l}")).collect::<Vec<_>>().join("\n"),
        );
        let cfg = load_from_str(&yaml).expect("parse config");
        let tls = RuntimeTls::build(&cfg).expect("build").expect("tls enabled");
        assert!(tls.runtime().has_certificate());

        // 构造一张私钥不匹配的证书，prepare 必须失败
        let mut bad = certificate_config("bad-cert", "bad.example.com");
        bad.key_pem = key_pem; // 与 bad 的 cert_pem 不匹配
        assert!(tls.prepare_snapshot(&[bad]).is_err());
        // 旧证书仍然可用
        assert!(tls.runtime().has_certificate());
    }
}
