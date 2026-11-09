//! 通知 Provider：邮件与短信均可插拔。
//!
//! 默认 `log` 仅适用于本地开发，不会输出验证码等敏感内容；生产环境应配置 `webhook`
//! 指向企业邮件/短信网关。上游服务只需实现相同的 HTTP 契约即可替换供应商。

use async_trait::async_trait;
use serde_json::json;

use crate::config::NotificationConfig;
use crate::shared::{AppError, AppResult};

#[async_trait]
pub trait NotificationProvider: Send + Sync {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> AppResult<()>;
    async fn send_sms(&self, phone: &str, body: &str) -> AppResult<()>;
    fn name(&self) -> &'static str;
}

pub struct LogNotificationProvider;

#[async_trait]
impl NotificationProvider for LogNotificationProvider {
    async fn send_email(&self, to: &str, subject: &str, _body: &str) -> AppResult<()> {
        tracing::info!(provider = "log", channel = "email", to = %crate::shared::util::mask_email(to), subject = %subject, "开发模式邮件通知已记录（正文包含敏感信息，未写入日志）");
        Ok(())
    }

    async fn send_sms(&self, phone: &str, _body: &str) -> AppResult<()> {
        tracing::info!(provider = "log", channel = "sms", to = %crate::shared::util::mask_phone(phone), "开发模式短信通知已记录（正文包含敏感信息，未写入日志）");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "log"
    }
}

pub struct WebhookNotificationProvider {
    client: reqwest::Client,
    url: String,
    token: String,
    from_email: String,
    from_name: String,
}

impl WebhookNotificationProvider {
    pub fn new(config: &NotificationConfig, client: reqwest::Client) -> AppResult<Self> {
        if config.webhook_url.trim().is_empty() {
            return Err(AppError::server_error(
                "通知 Provider 为 webhook 但未配置 URL",
            ));
        }
        Ok(Self {
            client,
            url: config.webhook_url.clone(),
            token: config.webhook_token.clone(),
            from_email: config.from_email.clone(),
            from_name: config.from_name.clone(),
        })
    }

    async fn post(&self, payload: serde_json::Value) -> AppResult<()> {
        let mut request = self.client.post(&self.url).json(&payload);
        if !self.token.is_empty() {
            request = request.bearer_auth(&self.token);
        }
        let response = request
            .send()
            .await
            .map_err(|error| AppError::unavailable(format!("通知网关请求失败: {error}")))?;
        if !response.status().is_success() {
            return Err(AppError::unavailable(format!(
                "通知网关返回状态 {}",
                response.status()
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl NotificationProvider for WebhookNotificationProvider {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> AppResult<()> {
        self.post(json!({
            "channel": "email",
            "to": to,
            "subject": subject,
            "body": body,
            "from": { "email": self.from_email, "name": self.from_name },
        }))
        .await
    }

    async fn send_sms(&self, phone: &str, body: &str) -> AppResult<()> {
        self.post(json!({
            "channel": "sms",
            "to": phone,
            "body": body,
        }))
        .await
    }

    fn name(&self) -> &'static str {
        "webhook"
    }
}

pub fn build_provider(
    config: &NotificationConfig,
    client: reqwest::Client,
) -> AppResult<std::sync::Arc<dyn NotificationProvider>> {
    match config.provider.as_str() {
        "log" => Ok(std::sync::Arc::new(LogNotificationProvider)),
        "webhook" => Ok(std::sync::Arc::new(WebhookNotificationProvider::new(
            config, client,
        )?)),
        other => Err(AppError::server_error(format!(
            "未知的通知 Provider: {other}（支持 log/webhook）"
        ))),
    }
}
