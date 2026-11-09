//! WebAuthn / Passkey 支持。

use serde_json::Value;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Webauthn, WebauthnBuilder,
};

use crate::config::WebauthnConfig;
use crate::shared::{AppError, AppResult};

pub struct WebauthnService {
    inner: Webauthn,
    rp_id: String,
}

impl WebauthnService {
    pub fn new(config: &WebauthnConfig) -> AppResult<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }
        if config.rp_id.trim().is_empty() || config.rp_origin.trim().is_empty() {
            return Err(AppError::server_error(
                "WebAuthn 已启用但 rp_id / rp_origin 未配置",
            ));
        }
        let origin = Url::parse(&config.rp_origin)
            .map_err(|error| AppError::server_error(format!("WebAuthn rp_origin 无效: {error}")))?;
        let builder = WebauthnBuilder::new(&config.rp_id, &origin)
            .map_err(|error| AppError::server_error(format!("WebAuthn 配置无效: {error}")))?;
        let inner = builder
            .rp_name(if config.rp_name.trim().is_empty() {
                &config.rp_id
            } else {
                &config.rp_name
            })
            .build()
            .map_err(|error| AppError::server_error(format!("WebAuthn 初始化失败: {error}")))?;
        Ok(Some(Self {
            inner,
            rp_id: config.rp_id.clone(),
        }))
    }

    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub fn start_registration(
        &self,
        user_id: Uuid,
        username: &str,
        display_name: &str,
    ) -> AppResult<(CreationChallengeResponse, PasskeyRegistration)> {
        self.inner
            .start_passkey_registration(user_id, username, display_name, None)
            .map_err(|error| AppError::bad_request(format!("无法开始 Passkey 注册: {error}")))
    }

    pub fn finish_registration(&self, response: &Value, state: &Value) -> AppResult<Passkey> {
        let credential: RegisterPublicKeyCredential = serde_json::from_value(response.clone())
            .map_err(|_| AppError::bad_request("Passkey 注册响应格式错误"))?;
        let registration: PasskeyRegistration = serde_json::from_value(state.clone())
            .map_err(|_| AppError::bad_request("Passkey 注册状态已失效"))?;
        self.inner
            .finish_passkey_registration(&credential, &registration)
            .map_err(|error| AppError::bad_request(format!("Passkey 注册校验失败: {error}")))
    }

    pub fn start_authentication(
        &self,
        passkeys: &[Passkey],
    ) -> AppResult<(RequestChallengeResponse, PasskeyAuthentication)> {
        if passkeys.is_empty() {
            return Err(AppError::bad_request("没有可用的 Passkey"));
        }
        self.inner
            .start_passkey_authentication(passkeys)
            .map_err(|error| AppError::bad_request(format!("无法开始 Passkey 认证: {error}")))
    }

    pub fn finish_authentication(
        &self,
        response: &Value,
        state: &Value,
    ) -> AppResult<AuthenticationResult> {
        let credential: PublicKeyCredential = serde_json::from_value(response.clone())
            .map_err(|_| AppError::bad_request("Passkey 认证响应格式错误"))?;
        let authentication: PasskeyAuthentication = serde_json::from_value(state.clone())
            .map_err(|_| AppError::bad_request("Passkey 认证状态已失效"))?;
        self.inner
            .finish_passkey_authentication(&credential, &authentication)
            .map_err(|error| AppError::bad_request(format!("Passkey 认证校验失败: {error}")))
    }
}

pub fn passkey_from_json(value: &Value) -> AppResult<Passkey> {
    serde_json::from_value(value.clone()).map_err(|_| AppError::server_error("Passkey 数据损坏"))
}
