//! SAML 2.0 身份提供方（IdP）与服务提供方（SP）配置管理。
//!
//! 使用纯 Rust `saml` crate 完成 XML 签名、签名的结构性验证（XSW 防护）、
//! 时间窗口、Audience/Recipient/InResponseTo 校验与防重放。

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::bootstrap::AppState;
use crate::domain::{Identity, SamlIdpConfig, SamlSpConfig};
use crate::shared::{AppError, AppResult};

/// SAML 响应分发指令，由 API 层转换为 HTTP 响应。
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SamlDispatch {
    Redirect {
        url: String,
    },
    Post {
        action: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        saml_request: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        saml_response: Option<String>,
        relay_state: Option<String>,
    },
}

impl SamlDispatch {
    fn from_binding(dispatch: saml::Dispatch) -> Self {
        match dispatch {
            saml::Dispatch::Redirect(url) => Self::Redirect {
                url: url.to_string(),
            },
            saml::Dispatch::Post(form) => Self::Post {
                action: form.action.to_string(),
                saml_request: form.saml_request,
                saml_response: form.saml_response,
                relay_state: form.relay_state,
            },
        }
    }
}

/// SAML 表单提交（POST Binding）。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SamlForm {
    #[serde(rename = "SAMLRequest", default)]
    pub saml_request: Option<String>,
    #[serde(rename = "SAMLResponse", default)]
    pub saml_response: Option<String>,
    #[serde(rename = "RelayState", default)]
    pub relay_state: Option<String>,
}

/// SP 注册/更新输入。
#[derive(Debug, Clone, Deserialize)]
pub struct SamlSpInput {
    pub code: String,
    pub name: String,
    #[serde(default)]
    pub metadata_xml: Option<String>,
    #[serde(default)]
    pub entity_id: Option<String>,
    #[serde(default)]
    pub acs_url: Option<String>,
    #[serde(default)]
    pub slo_url: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub name_id_format: Option<String>,
    #[serde(default)]
    pub attribute_mapping: Option<Value>,
    #[serde(default)]
    pub certificate_pem: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

/// IdP 配置更新输入。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SamlIdpUpdate {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub entity_id: Option<String>,
    #[serde(default)]
    pub idp_name: Option<String>,
}

struct IdpMaterial {
    idp: saml::IdentityProvider,
    config: SamlIdpConfig,
}

fn saml_err(action: &str, error: impl std::fmt::Display) -> AppError {
    tracing::warn!(action, error = %error, "SAML 处理失败");
    AppError::bad_request(format!("SAML 处理失败：{error}"))
}

fn system_now() -> SystemTime {
    SystemTime::now()
}

impl AppState {
    /// 读取租户的 IdP 配置，不存在时自动生成自签名证书初始化。
    pub async fn saml_idp_config(&self, tenant_id: Uuid) -> AppResult<SamlIdpConfig> {
        if let Some(config) = sqlx::query_as::<_, SamlIdpConfig>(
            "SELECT * FROM saml_idp_configs WHERE tenant_id = $1 ORDER BY created_at LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        {
            return Ok(config);
        }
        self.saml_create_idp_config(tenant_id, None, None).await
    }

    /// 创建（或重新生成）IdP 配置与证书。
    pub async fn saml_create_idp_config(
        &self,
        tenant_id: Uuid,
        entity_id: Option<String>,
        idp_name: Option<String>,
    ) -> AppResult<SamlIdpConfig> {
        self.ensure_tenant(tenant_id).await?;
        let base = self.config.base_url();
        let entity_id = entity_id
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| self.config.saml.idp_entity_id.clone());
        let idp_name = idp_name.unwrap_or_else(|| self.config.saml.idp_name.clone());
        let (certificate_pem, private_pem) =
            crate::security::crypto::generate_self_signed_certificate(&format!(
                "saml-idp-{tenant_id}"
            ))
            .map_err(|error| AppError::server_error(format!("生成 SAML 证书失败: {error}")))?;
        let encrypted = self.crypto.encrypt_str(&private_pem)?;
        let config = sqlx::query_as::<_, SamlIdpConfig>(
            "INSERT INTO saml_idp_configs
                (tenant_id, enabled, entity_id, idp_name, sso_url, slo_url, certificate_pem,
                 private_key_encrypted)
             VALUES ($1, TRUE, $2, $3, $4, $5, $6, $7)
             RETURNING *",
        )
        .bind(tenant_id)
        .bind(&entity_id)
        .bind(&idp_name)
        .bind(format!("{base}/saml/sso"))
        .bind(format!("{base}/saml/slo"))
        .bind(&certificate_pem)
        .bind(&encrypted)
        .fetch_one(&self.pool)
        .await?;
        let _ = sqlx::query(
            "UPDATE saml_idp_configs SET metadata_xml = NULL, updated_at = now() WHERE id = $1",
        )
        .bind(config.id)
        .execute(&self.pool)
        .await;
        Ok(config)
    }

    pub async fn saml_update_idp_config(
        &self,
        tenant_id: Uuid,
        input: SamlIdpUpdate,
    ) -> AppResult<SamlIdpConfig> {
        let current = self.saml_idp_config(tenant_id).await?;
        let config = sqlx::query_as::<_, SamlIdpConfig>(
            "UPDATE saml_idp_configs
             SET enabled = COALESCE($2, enabled),
                 entity_id = COALESCE($3, entity_id),
                 idp_name = COALESCE($4, idp_name),
                 metadata_xml = NULL,
                 updated_at = now()
             WHERE id = $1
             RETURNING *",
        )
        .bind(current.id)
        .bind(input.enabled)
        .bind(input.entity_id.filter(|value| !value.trim().is_empty()))
        .bind(input.idp_name.filter(|value| !value.trim().is_empty()))
        .fetch_one(&self.pool)
        .await?;
        Ok(config)
    }

    /// 轮换 IdP 签名证书与私钥。
    pub async fn saml_rotate_idp_certificate(&self, tenant_id: Uuid) -> AppResult<SamlIdpConfig> {
        let current = self.saml_idp_config(tenant_id).await?;
        let (certificate_pem, private_pem) =
            crate::security::crypto::generate_self_signed_certificate(&format!(
                "saml-idp-{tenant_id}"
            ))
            .map_err(|error| AppError::server_error(format!("生成 SAML 证书失败: {error}")))?;
        let encrypted = self.crypto.encrypt_str(&private_pem)?;
        let config = sqlx::query_as::<_, SamlIdpConfig>(
            "UPDATE saml_idp_configs
             SET certificate_pem = $2, private_key_encrypted = $3, metadata_xml = NULL, updated_at = now()
             WHERE id = $1
             RETURNING *",
        )
        .bind(current.id)
        .bind(&certificate_pem)
        .bind(&encrypted)
        .fetch_one(&self.pool)
        .await?;
        Ok(config)
    }

    async fn idp_material(&self, tenant_id: Uuid) -> AppResult<IdpMaterial> {
        let config = self.saml_idp_config(tenant_id).await?;
        if !config.enabled {
            return Err(AppError::forbidden("SAML IdP 已禁用"));
        }
        let private_pem = self.crypto.decrypt_str(&config.private_key_encrypted)?;
        let certificate = saml::X509Certificate::from_pem(config.certificate_pem.as_bytes())
            .map_err(|error| saml_err("parse_certificate", error))?;
        if certificate.not_after() <= system_now() {
            return Err(AppError::server_error("SAML IdP 证书已过期，请轮换证书"));
        }
        let keypair = saml::KeyPair::from_pkcs8_pem(private_pem.as_bytes())
            .and_then(|pair| pair.with_certificate(certificate))
            .map_err(|error| saml_err("build_keypair", error))?;
        let base = self.config.base_url();
        let idp = saml::IdentityProvider::new(saml::IdentityProviderConfig {
            entity_id: config.entity_id.clone(),
            sso: vec![
                saml::Endpoint::redirect(format!("{base}/saml/sso"), 0, true),
                saml::Endpoint::post(format!("{base}/saml/sso"), 1, false),
            ],
            slo: vec![
                saml::Endpoint::redirect(format!("{base}/saml/slo"), 0, true),
                saml::Endpoint::post(format!("{base}/saml/slo"), 1, false),
            ],
            artifact_resolution: vec![],
            supported_name_id_formats: vec![
                saml::NameIdFormat::Persistent,
                saml::NameIdFormat::EmailAddress,
            ],
            default_name_id_format: saml::NameIdFormat::Persistent,
            signing_key: keypair,
            decryption_key: None,
            want_authn_requests_signed: self.config.saml.want_authn_requests_signed,
            assertion_signing: saml::IdpAssertionSigning {
                sign_responses: true,
                sign_assertions: true,
            },
            encrypt_assertions_when_possible: true,
            logout_signing: saml::IdpLogoutSigning {
                sign_requests: true,
                sign_responses: true,
            },
            logout_want_signed: saml::IdpLogoutWantSigned {
                requests: true,
                responses: true,
            },
            default_session_duration: Duration::from_secs(
                self.config.security.session_ttl_secs.max(60),
            ),
            max_authn_request_age: saml::IdentityProviderConfig::DEFAULT_MAX_AUTHN_REQUEST_AGE,
            default_peer_crypto_policy: saml::PeerCryptoPolicy::strong_defaults(),
            outbound_signature_algorithm: saml::SignatureAlgorithm::RsaSha256,
            outbound_digest_algorithm: saml::DigestAlgorithm::Sha256,
            outbound_c14n: saml::C14nAlgorithm::ExclusiveCanonical,
            outbound_data_encryption_algorithm: saml::DataEncryptionAlgorithm::Aes256Gcm,
            outbound_key_transport_algorithm: saml::KeyTransportAlgorithm::RsaOaep,
        })
        .map_err(|error| saml_err("build_idp", error))?;
        Ok(IdpMaterial { idp, config })
    }

    /// 生成 IdP Metadata XML。
    pub async fn saml_metadata(&self, tenant_id: Uuid, sign: bool) -> AppResult<String> {
        let material = self.idp_material(tenant_id).await?;
        let xml = material
            .idp
            .metadata_xml(sign)
            .map_err(|error| saml_err("metadata", error))?;
        if sign {
            let _ = sqlx::query(
                "UPDATE saml_idp_configs SET metadata_xml = $2, updated_at = now() WHERE id = $1",
            )
            .bind(material.config.id)
            .bind(&xml)
            .execute(&self.pool)
            .await;
        }
        Ok(xml)
    }

    // ─────────────────────── SP 配置管理 ───────────────────────

    pub async fn saml_list_sp(&self, tenant_id: Uuid) -> AppResult<Vec<SamlSpConfig>> {
        Ok(sqlx::query_as::<_, SamlSpConfig>(
            "SELECT * FROM saml_sp_configs WHERE tenant_id = $1 ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn saml_get_sp(&self, tenant_id: Uuid, code: &str) -> AppResult<SamlSpConfig> {
        sqlx::query_as::<_, SamlSpConfig>(
            "SELECT * FROM saml_sp_configs WHERE tenant_id = $1 AND code = $2",
        )
        .bind(tenant_id)
        .bind(code)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::not_found("SAML SP 不存在"))
    }

    /// 注册或更新 SP；提供 metadata 时自动导入 ACS、SLO、EntityID 与证书。
    pub async fn saml_upsert_sp(
        &self,
        tenant_id: Uuid,
        input: SamlSpInput,
    ) -> AppResult<SamlSpConfig> {
        self.ensure_tenant(tenant_id).await?;
        if input.code.trim().is_empty() {
            return Err(AppError::validation("code", "SP 编码不能为空"));
        }
        let mut entity_id = input.entity_id.clone().unwrap_or_default();
        let mut acs_url = input.acs_url.clone().unwrap_or_default();
        let mut slo_url = input.slo_url.clone();
        let mut name_id_format = input
            .name_id_format
            .clone()
            .unwrap_or_else(|| "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_string());
        let mut certificate_pem = input.certificate_pem.clone();
        let metadata_xml = input.metadata_xml.clone().unwrap_or_default();

        if !metadata_xml.trim().is_empty() {
            let descriptor = saml::SpDescriptor::from_metadata_xml(metadata_xml.as_bytes())
                .map_err(|error| saml_err("parse_sp_metadata", error))?;
            entity_id = descriptor.entity_id.clone();
            let acs = descriptor
                .default_acs()
                .ok_or_else(|| AppError::validation("metadata_xml", "元数据缺少 ACS 端点"))?;
            acs_url = acs.url.clone();
            slo_url = descriptor
                .single_logout_services
                .first()
                .map(|endpoint| endpoint.url.clone())
                .or(slo_url);
            if let Some(format) = descriptor.supported_name_id_formats.first() {
                name_id_format = format.as_uri().to_string();
            }
            certificate_pem = descriptor
                .signing_certs
                .first()
                .map(|cert| {
                    let der = cert.to_base64_x509();
                    format!("-----BEGIN CERTIFICATE-----\n{der}\n-----END CERTIFICATE-----\n")
                })
                .or(certificate_pem);
        }

        if entity_id.trim().is_empty() {
            return Err(AppError::validation("entity_id", "缺少 SP EntityID"));
        }
        if acs_url.trim().is_empty() {
            return Err(AppError::validation("acs_url", "缺少 SP ACS URL"));
        }
        validate_absolute_url(&acs_url, true)?;
        if let Some(slo) = slo_url.as_deref() {
            validate_absolute_url(slo, true)?;
        }
        let audience = input
            .audience
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| entity_id.clone());
        let mapping = input.attribute_mapping.unwrap_or_else(
            || json!({"email": "email", "display_name": "displayName", "username": "username"}),
        );
        let status = input.status.unwrap_or_else(|| "active".to_string());

        let config = sqlx::query_as::<_, SamlSpConfig>(
            "INSERT INTO saml_sp_configs
                (tenant_id, code, entity_id, name, metadata_xml, acs_url, slo_url, audience,
                 name_id_format, attribute_mapping, certificate_pem, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             ON CONFLICT (tenant_id, code) DO UPDATE SET
                 entity_id = EXCLUDED.entity_id,
                 name = EXCLUDED.name,
                 metadata_xml = EXCLUDED.metadata_xml,
                 acs_url = EXCLUDED.acs_url,
                 slo_url = EXCLUDED.slo_url,
                 audience = EXCLUDED.audience,
                 name_id_format = EXCLUDED.name_id_format,
                 attribute_mapping = EXCLUDED.attribute_mapping,
                 certificate_pem = EXCLUDED.certificate_pem,
                 status = EXCLUDED.status,
                 updated_at = now()
             RETURNING *",
        )
        .bind(tenant_id)
        .bind(input.code.trim())
        .bind(&entity_id)
        .bind(&input.name)
        .bind(&metadata_xml)
        .bind(&acs_url)
        .bind(&slo_url)
        .bind(&audience)
        .bind(&name_id_format)
        .bind(&mapping)
        .bind(&certificate_pem)
        .bind(&status)
        .fetch_one(&self.pool)
        .await?;
        Ok(config)
    }

    pub async fn saml_delete_sp(&self, tenant_id: Uuid, code: &str) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM saml_sp_configs WHERE tenant_id = $1 AND code = $2")
            .bind(tenant_id)
            .bind(code)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::not_found("SAML SP 不存在"));
        }
        Ok(())
    }

    // ─────────────────────── SSO ───────────────────────

    /// 处理 SAML AuthnRequest（Redirect 或 POST Binding），签发 Response。
    pub async fn saml_handle_sso(
        &self,
        tenant_id: Uuid,
        binding: saml::Binding,
        wire_body: &[u8],
        relay_state: Option<&str>,
        identity: &Identity,
    ) -> AppResult<SamlDispatch> {
        let material = self.idp_material(tenant_id).await?;
        let decoded = saml::decode_wire(wire_body, binding, saml::WireDirection::Request)
            .map_err(|error| saml_err("decode_authn_request", error))?;
        let xml = String::from_utf8_lossy(&decoded.xml).to_string();
        let sp_config = self.match_sp_by_issuer(tenant_id, &xml).await?;
        let descriptor = saml::SpDescriptor::from_metadata_xml(sp_config.metadata_xml.as_bytes())
            .map_err(|error| saml_err("parse_sp_metadata", error))?;
        let expected_destination = format!("{}/saml/sso", self.config.base_url());

        // 若 SP 未提供 metadata，则用配置中的 ACS 构造最小描述符。
        let parsed = material
            .idp
            .consume_authn_request_wire(saml::ConsumeAuthnRequestWire {
                sp: &descriptor,
                peer_crypto_policy: None,
                max_authn_request_age: None,
                wire_body,
                binding,
                relay_state: if binding == saml::Binding::HttpPost {
                    relay_state.or(decoded.relay_state.as_deref())
                } else {
                    decoded.relay_state.as_deref()
                },
                expected_destination: &expected_destination,
                now: system_now(),
                clock_skew: Duration::from_secs(self.config.saml.clock_skew_secs),
            })
            .map_err(|error| saml_err("consume_authn_request", error))?;

        let name_id = resolve_name_id(&sp_config, identity);
        let attributes = build_attributes(&sp_config, identity);
        let response = material
            .idp
            .issue_response(saml::IssueResponse {
                sp: &descriptor,
                in_response_to: &parsed,
                name_id,
                attributes,
                authn_instant: system_now(),
                session_index: Uuid::now_v7().to_string(),
                session_not_on_or_after: Some(
                    system_now()
                        + Duration::from_secs(self.config.security.session_ttl_secs.max(60)),
                ),
                authn_context_class_ref: saml::AuthnContextClassRef::PasswordProtectedTransport,
                force_encrypt_assertion: None,
                now: system_now(),
                assertion_lifetime: Duration::from_secs(
                    self.config.saml.assertion_lifetime_secs.max(60),
                ),
                subject_confirmation_lifetime: Duration::from_secs(
                    self.config.saml.assertion_lifetime_secs.max(60),
                ),
                holder_of_key_cert: None,
            })
            .map_err(|error| saml_err("issue_response", error))?;

        crate::application::audit::record(
            &self.pool,
            crate::application::audit::AuditEntry::new("saml.sso.issued")
                .tenant(tenant_id)
                .actor(identity.id)
                .resource("saml_sp", sp_config.entity_id.clone())
                .detail(json!({ "sp": sp_config.code })),
        )
        .await?;

        match response {
            saml::SsoResponseDispatch::Post(form) => Ok(SamlDispatch::Post {
                action: form.action.to_string(),
                saml_request: None,
                saml_response: Some(form.saml_response),
                relay_state: form.relay_state,
            }),
            saml::SsoResponseDispatch::Artifact(_) => {
                Err(AppError::bad_request("不支持 HTTP-Artifact 绑定"))
            }
        }
    }

    /// 处理 SAML Single Logout（IdP 侧）。
    pub async fn saml_handle_slo(
        &self,
        tenant_id: Uuid,
        binding: saml::Binding,
        wire_body: &[u8],
    ) -> AppResult<SamlDispatch> {
        let material = self.idp_material(tenant_id).await?;
        let decoded = saml::decode_wire(wire_body, binding, saml::WireDirection::Request)
            .map_err(|error| saml_err("decode_logout_request", error))?;
        let xml = String::from_utf8_lossy(&decoded.xml).to_string();
        let sp_config = self.match_sp_by_issuer(tenant_id, &xml).await?;
        let descriptor = saml::SpDescriptor::from_metadata_xml(sp_config.metadata_xml.as_bytes())
            .map_err(|error| saml_err("parse_sp_metadata", error))?;
        let expected_destination = format!("{}/saml/slo", self.config.base_url());
        let parsed = material
            .idp
            .consume_logout_request_wire(saml::ConsumeLogoutRequestWire {
                sp: &descriptor,
                peer_crypto_policy: None,
                wire_body,
                binding,
                expected_destination: &expected_destination,
                now: system_now(),
                clock_skew: Duration::from_secs(self.config.saml.clock_skew_secs),
            })
            .map_err(|error| saml_err("consume_logout_request", error))?;

        if let Ok(identity_id) = Uuid::parse_str(parsed.name_id.value.trim()) {
            self.revoke_all_sessions(identity_id, "saml_slo").await?;
        }
        let response_binding = saml::Binding::HttpRedirect;
        let dispatch = material
            .idp
            .build_logout_response(
                &descriptor,
                &parsed,
                saml::LogoutStatus::Success,
                decoded.relay_state.as_deref(),
                response_binding,
            )
            .map_err(|error| saml_err("build_logout_response", error))?;
        Ok(SamlDispatch::from_binding(dispatch))
    }

    async fn match_sp_by_issuer(&self, tenant_id: Uuid, xml: &str) -> AppResult<SamlSpConfig> {
        let configs = self.saml_list_sp(tenant_id).await?;
        configs
            .into_iter()
            .filter(|config| config.status == "active")
            .find(|config| xml.contains(&config.entity_id))
            .ok_or_else(|| AppError::bad_request("未注册的 SAML SP"))
    }

    // ─────────────────────── SP 侧消费响应（用于第三方 SAML 登录） ───────────────────────

    /// 在认证中心作为 SP 的场景下校验第三方 IdP 返回的 SAMLResponse。
    pub async fn saml_consume_sp_response(
        &self,
        provider: &crate::domain::IdentityProvider,
        saml_response: &[u8],
        relay_state: Option<&str>,
    ) -> AppResult<saml::Identity> {
        let metadata = provider
            .config
            .get("metadata_xml")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::validation("provider", "SAML 提供商缺少 metadata_xml"))?;
        let descriptor = saml::IdpDescriptor::from_metadata_xml(metadata.as_bytes())
            .map_err(|error| saml_err("parse_idp_metadata", error))?;
        let acs = provider
            .config
            .get("acs_url")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| {
                format!("{}/api/v1/auth/federated/saml/acs", self.config.base_url())
            });
        let sp = saml::ServiceProvider::new(saml::ServiceProviderConfig {
            entity_id: provider
                .config
                .get("sp_entity_id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| format!("{}/saml/sp", self.config.base_url())),
            acs: vec![saml::SsoResponseEndpoint::post(acs.clone(), 0, true)],
            slo: vec![],
            name_id_formats: vec![
                saml::NameIdFormat::Persistent,
                saml::NameIdFormat::EmailAddress,
            ],
            signing_key: None,
            decryption_key: None,
            sign_authn_requests: false,
            want_signed: saml::SpWantSigned {
                response: false,
                assertions: true,
            },
            allow_unsolicited: false,
            logout_signing: saml::SpLogoutSigning {
                sign_requests: false,
                sign_responses: false,
            },
            logout_want_signed: saml::SpLogoutWantSigned {
                requests: false,
                responses: false,
            },
            default_peer_crypto_policy: saml::PeerCryptoPolicy::strong_defaults(),
            outbound_signature_algorithm: saml::SignatureAlgorithm::RsaSha256,
            outbound_digest_algorithm: saml::DigestAlgorithm::Sha256,
        })
        .map_err(|error| saml_err("build_sp", error))?;

        sp.consume_response(saml::ConsumeResponse {
            idp: &descriptor,
            peer_crypto_policy: None,
            saml_response,
            binding: saml::SsoResponseBinding::HttpPost,
            relay_state,
            tracker: None,
            expected_destination: &acs,
            now: system_now(),
            clock_skew: Duration::from_secs(self.config.saml.clock_skew_secs),
            replay_cache: Some(self.saml_replay.as_ref()),
            replay_mode: saml::ReplayMode::All,
            holder_of_key_cert: None,
        })
        .map_err(|error| saml_err("consume_response", error))
    }
}

fn resolve_name_id(sp: &SamlSpConfig, identity: &Identity) -> saml::NameId {
    match sp.name_id_format.as_str() {
        "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress" => {
            if let Some(email) = &identity.email {
                return saml::NameId::email(email.clone());
            }
            saml::NameId::persistent_for_sp(identity.id.to_string(), sp.entity_id.clone())
        }
        _ => saml::NameId::persistent_for_sp(identity.id.to_string(), sp.entity_id.clone()),
    }
}

fn build_attributes(sp: &SamlSpConfig, identity: &Identity) -> Vec<saml::Attribute> {
    let mut attributes = vec![
        saml::Attribute::single("username", identity.username.clone()),
        saml::Attribute::single("uid", identity.id.to_string()),
    ];
    if let Some(display_name) = &identity.display_name {
        attributes.push(saml::Attribute::display_name(display_name.clone()));
    }
    if let Some(email) = &identity.email {
        attributes.push(saml::Attribute::email(email.clone()));
    }
    if let Some(phone) = &identity.phone {
        attributes.push(saml::Attribute::single("phone", phone.clone()));
    }
    if let Some(map) = sp.attribute_mapping.as_object() {
        for (target, source) in map {
            let value = match source.as_str() {
                Some("email") => identity.email.clone(),
                Some("phone") => identity.phone.clone(),
                Some("display_name") => identity.display_name.clone(),
                Some("username") => Some(identity.username.clone()),
                Some("identity_id") | Some("sub") => Some(identity.id.to_string()),
                Some(other) => identity
                    .metadata
                    .get(other)
                    .and_then(Value::as_str)
                    .map(str::to_string),
                None => None,
            };
            if let Some(value) = value {
                if !attributes.iter().any(|attribute| &attribute.name == target) {
                    attributes.push(saml::Attribute::single(target.clone(), value));
                }
            }
        }
    }
    attributes
}

fn validate_absolute_url(value: &str, allow_http: bool) -> AppResult<()> {
    let parsed =
        url::Url::parse(value.trim()).map_err(|_| AppError::validation("url", "URL 格式不合法"))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if allow_http => Ok(()),
        _ => Err(AppError::validation("url", "URL 必须使用 HTTPS")),
    }
}
