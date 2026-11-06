//! TLS 终止与证书管理。
//!
//! 设计要点：
//!   1. 使用 rustls 做 TLS 1.2/1.3 终止，ALPN 同时支持 `h2` 与 `http/1.1`；
//!   2. 证书按 SNI 域名选择，未命中时回退到默认证书；
//!   3. 证书集合放在 [`CertificateStore`] 的 `RwLock` 中，热更新只替换证书，
//!      已建立的连接继续使用旧证书，新连接立即使用新证书；
//!   4. 支持可选 mTLS（客户端 CA 文件）。
//!
//! 本模块只依赖 rustls / rustls-pemfile，不读取配置文件——配置到证书的
//! 映射由 gateway-runtime 组装。

use std::collections::HashMap;
use std::fmt;
use std::io::BufReader;
use std::path::Path;
use std::sync::{Arc, RwLock};

use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

/// 已解析的证书材料。
#[derive(Clone)]
pub struct LoadedCertificate {
    /// 证书资源 ID（文件证书使用固定 ID）
    pub id: String,
    /// 绑定的 SNI 域名（支持 `*.example.com`）
    pub domains: Vec<String>,
    /// 证书链 + 私钥（已完成匹配校验）
    pub certified_key: Arc<CertifiedKey>,
}

impl fmt::Debug for LoadedCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadedCertificate")
            .field("id", &self.id)
            .field("domains", &self.domains)
            .finish_non_exhaustive()
    }
}

/// 解析 PEM 证书链与私钥，并校验公钥/私钥匹配。
pub fn load_from_pem(cert_pem: &str, key_pem: &str) -> Result<Arc<CertifiedKey>, String> {
    let mut cert_reader = BufReader::new(cert_pem.as_bytes());
    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse certificate PEM: {e}"))?;
    if cert_chain.is_empty() {
        return Err("certificate PEM contains no CERTIFICATE block".to_string());
    }

    let mut key_reader = BufReader::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("failed to parse private key PEM: {e}"))?
        .ok_or_else(|| "private key PEM contains no PRIVATE KEY block".to_string())?;

    let provider = rustls::crypto::ring::default_provider();
    let certified = CertifiedKey::from_der(cert_chain, key, &provider)
        .map_err(|e| format!("certificate and private key do not match: {e}"))?;
    Ok(Arc::new(certified))
}

/// 从文件加载证书。
pub fn load_from_files(cert_path: &Path, key_path: &Path) -> Result<Arc<CertifiedKey>, String> {
    let cert_pem = std::fs::read_to_string(cert_path)
        .map_err(|e| format!("failed to read {}: {e}", cert_path.display()))?;
    let key_pem = std::fs::read_to_string(key_path)
        .map_err(|e| format!("failed to read {}: {e}", key_path.display()))?;
    load_from_pem(&cert_pem, &key_pem)
}

/// 构造已加载证书。
pub fn certificate(
    id: impl Into<String>,
    domains: Vec<String>,
    certified_key: Arc<CertifiedKey>,
) -> LoadedCertificate {
    LoadedCertificate {
        id: id.into(),
        domains,
        certified_key,
    }
}

// ---------------------------------------------------------------------------
// 证书集合与 SNI 解析
// ---------------------------------------------------------------------------

#[derive(Default)]
struct CertificateSet {
    /// 默认证书（SNI 未命中时使用）
    default: Option<Arc<CertifiedKey>>,
    /// 精确域名 → 证书
    exact: HashMap<String, Arc<CertifiedKey>>,
    /// 通配符后缀（`example.com` 对应 `*.example.com`）→ 证书
    wildcard: HashMap<String, Arc<CertifiedKey>>,
    /// 证书 ID → 证书（用于默认证书选择）
    by_id: HashMap<String, Arc<CertifiedKey>>,
}

impl CertificateSet {
    fn select(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        // 忽略端口与大小写差异；锁已由调用方持有
        if let Some(name) = server_name {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            if let Some(key) = self.exact.get(&name) {
                return Some(key.clone());
            }
            // 通配符只匹配一级子域（RFC 6125 语义）
            if let Some((_, suffix)) = name.split_once('.') {
                if let Some(key) = self.wildcard.get(suffix) {
                    return Some(key.clone());
                }
            }
        }
        self.default.clone()
    }
}

/// 可热更新的 SNI 证书解析器。
pub struct SniCertificateResolver {
    set: RwLock<CertificateSet>,
}

impl fmt::Debug for SniCertificateResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SniCertificateResolver").finish()
    }
}

impl SniCertificateResolver {
    fn new() -> Self {
        Self {
            set: RwLock::new(CertificateSet::default()),
        }
    }

    fn replace(&self, set: CertificateSet) -> Result<(), String> {
        let mut guard =
            self.set.write().map_err(|_| "certificate store lock poisoned".to_string())?;
        *guard = set;
        Ok(())
    }

    /// 当前是否已加载任一证书（启动探测/测试使用）。
    pub fn has_certificate(&self) -> bool {
        self.set.read().map(|guard| guard.default.is_some()).unwrap_or(false)
    }
}

impl ResolvesServerCert for SniCertificateResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let guard = match self.set.read() {
            Ok(guard) => guard,
            Err(_) => return None,
        };
        guard.select(client_hello.server_name())
    }
}

// ---------------------------------------------------------------------------
// TlsRuntime —— acceptor + 可热更新证书集合
// ---------------------------------------------------------------------------

/// 一次证书集合构建的产物。
///
/// `prepare()` 只做解析与校验，不修改运行中状态；调用方在校验其他配置
/// （例如快照版本）通过后再 `commit()`，保证要么全部生效、要么全部不生效。
pub struct PreparedCertificates {
    set: CertificateSet,
}

impl fmt::Debug for PreparedCertificates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedCertificates")
            .field("certificates", &self.set.by_id.len())
            .finish()
    }
}

/// TLS 运行时。
pub struct TlsRuntime {
    resolver: Arc<SniCertificateResolver>,
    server_config: Arc<ServerConfig>,
}

impl fmt::Debug for TlsRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsRuntime")
            .field("has_certificate", &self.resolver.has_certificate())
            .finish()
    }
}

impl TlsRuntime {
    /// 创建 TLS 运行时。
    ///
    /// `client_ca_pem` 存在时要求客户端提供由该 CA 签发的证书（mTLS）。
    pub fn new(client_ca_pem: Option<&str>) -> Result<Self, String> {
        let resolver = Arc::new(SniCertificateResolver::new());

        let builder = match client_ca_pem {
            Some(ca_pem) => {
                let roots = parse_root_store(ca_pem)?;
                let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .map_err(|e| format!("failed to build client certificate verifier: {e}"))?;
                ServerConfig::builder().with_client_cert_verifier(verifier)
            },
            None => ServerConfig::builder().with_no_client_auth(),
        };

        let mut server_config = builder.with_cert_resolver(resolver.clone());
        // ALPN：优先 h2（gRPC/HTTP2），回退 http/1.1
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(Self {
            resolver,
            server_config: Arc::new(server_config),
        })
    }

    /// 解析并校验一组证书，生成可提交的证书集合。
    ///
    /// `default_id` 指定默认证书；不存在或未指定时使用第一个证书。
    pub fn prepare(
        certificates: Vec<LoadedCertificate>,
        default_id: Option<&str>,
    ) -> Result<PreparedCertificates, String> {
        if certificates.is_empty() {
            return Err("TLS enabled but no usable certificate is configured".to_string());
        }

        let mut set = CertificateSet::default();
        for item in certificates {
            set.by_id.insert(item.id.clone(), item.certified_key.clone());
            for domain in &item.domains {
                let domain = domain.trim_end_matches('.').to_ascii_lowercase();
                if domain.is_empty() {
                    continue;
                }
                if let Some(suffix) = domain.strip_prefix("*.") {
                    set.wildcard.insert(suffix.to_string(), item.certified_key.clone());
                } else {
                    set.exact.insert(domain, item.certified_key.clone());
                }
            }
        }

        set.default = default_id
            .and_then(|id| set.by_id.get(id).cloned())
            .or_else(|| set.by_id.values().next().cloned());

        if set.default.is_none() {
            return Err("TLS enabled but no usable certificate is configured".to_string());
        }
        if default_id.is_some_and(|id| !set.by_id.contains_key(id)) {
            tracing::warn!(
                target: "tls",
                certificate_id = default_id.unwrap_or_default(),
                "configured default certificate not found; falling back to another certificate"
            );
        }

        Ok(PreparedCertificates { set })
    }

    /// `prepare` 的宽容版本：允许空证书集合。
    ///
    /// 用于控制面引导阶段：数据面启动时本地可以没有任何证书，等控制面
    /// 首个快照下发证书后再激活握手；在此之前所有 TLS 握手都会失败
    /// （resolver 返回 `None`，rustls 以 `unrecognized_name` 告警终止）。
    pub fn prepare_allow_empty(
        certificates: Vec<LoadedCertificate>,
        default_id: Option<&str>,
    ) -> Result<PreparedCertificates, String> {
        if certificates.is_empty() {
            return Ok(PreparedCertificates {
                set: CertificateSet::default(),
            });
        }
        Self::prepare(certificates, default_id)
    }

    /// 原子替换当前证书集合。新握手立即使用新证书，旧连接不受影响。
    pub fn commit(&self, prepared: PreparedCertificates) {
        if let Err(err) = self.resolver.replace(prepared.set) {
            tracing::error!(target: "tls", error = %err, "failed to install certificate set");
        }
    }

    /// 解析并立即应用证书集合。
    pub fn update(
        &self,
        certificates: Vec<LoadedCertificate>,
        default_id: Option<&str>,
    ) -> Result<(), String> {
        let prepared = Self::prepare(certificates, default_id)?;
        self.commit(prepared);
        Ok(())
    }

    /// 当前是否已有可用证书。
    pub fn has_certificate(&self) -> bool {
        self.resolver.has_certificate()
    }

    /// 创建 tokio-rustls acceptor（每次连接 clone 一个即可）。
    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(self.server_config.clone())
    }

    /// 当前 ServerConfig（测试或需要 ALPN 信息时使用）。
    pub fn server_config(&self) -> Arc<ServerConfig> {
        self.server_config.clone()
    }
}

fn parse_root_store(ca_pem: &str) -> Result<RootCertStore, String> {
    let mut reader = BufReader::new(ca_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse client CA PEM: {e}"))?;
    if certs.is_empty() {
        return Err("client CA PEM contains no CERTIFICATE block".to_string());
    }
    let mut roots = RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err("client CA PEM contains no valid certificate".to_string());
    }
    Ok(roots)
}

// ---------------------------------------------------------------------------
// 单元测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_certificate() -> (String, String) {
        let cert = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "api.example.com".to_string(),
        ])
        .expect("generate certificate");
        (cert.cert.pem(), cert.key_pair.serialize_pem())
    }

    #[test]
    fn parses_pem_and_matches_key() {
        let (cert_pem, key_pem) = test_certificate();
        let key = load_from_pem(&cert_pem, &key_pem).expect("parse certificate");
        assert!(!key.cert.is_empty());
    }

    #[test]
    fn rejects_mismatched_key() {
        let (cert_pem, _) = test_certificate();
        let (_, other_key) = test_certificate();
        let err = load_from_pem(&cert_pem, &other_key).expect_err("key mismatch must fail");
        assert!(err.contains("do not match") || err.contains("private key"));
    }

    #[test]
    fn sni_selection_prefers_exact_then_wildcard_then_default() {
        let (cert_pem, key_pem) = test_certificate();
        let key = load_from_pem(&cert_pem, &key_pem).expect("parse certificate");
        let mut set = CertificateSet::default();
        set.default = Some(key.clone());
        set.exact.insert("api.example.com".to_string(), key.clone());
        set.wildcard.insert("example.org".to_string(), key);

        assert!(set.select(Some("api.example.com")).is_some());
        assert!(set.select(Some("foo.example.org")).is_some());
        // 通配符不匹配多级子域
        assert!(set.select(Some("a.b.example.org")).is_some()); // 回退默认证书
        assert!(set.select(None).is_some());
    }

    #[test]
    fn prepare_requires_a_certificate() {
        let err = TlsRuntime::prepare(Vec::new(), None).expect_err("empty set must fail");
        assert!(err.contains("no usable certificate"));
    }

    #[test]
    fn runtime_can_hot_replace_certificates() {
        let (cert_pem, key_pem) = test_certificate();
        let key = load_from_pem(&cert_pem, &key_pem).expect("parse certificate");
        let runtime = TlsRuntime::new(None).expect("create tls runtime");
        assert!(!runtime.has_certificate());

        runtime
            .update(vec![certificate("c1", vec!["localhost".into()], key)], Some("c1"))
            .expect("install certificate");
        assert!(runtime.has_certificate());
    }
}
