//! 认证中心集成测试。
//!
//! 需要真实 PostgreSQL 与 Redis。运行方式：
//!
//! ```bash
//! AUTH__DATABASE__URL='postgres://auth_center:auth_center@localhost:5432/auth_center_test' \
//! AUTH__REDIS__URL='redis://localhost:6379/8' \
//! AUTH__SECURITY__MASTER_KEY='3geuNbeEwCC5OwBz78oo3fbuecUVKlNa4NmP1beftWQ=' \
//! cargo test --test integration -- --ignored --test-threads=1
//! ```
//!
//! 测试会真实执行 Migration，并验证签名密钥落库加密、JWT 签发/验签与 JWKS 输出。

use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use auth_center::bootstrap::AppState;
use auth_center::config::Settings;
use auth_center::domain::TokenClaims;

fn test_settings() -> Settings {
    let database_url = std::env::var("AUTH_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("AUTH__DATABASE__URL"))
        .expect("必须设置 AUTH_TEST_DATABASE_URL 或 AUTH__DATABASE__URL 指向测试数据库");
    std::env::set_var("AUTH__DATABASE__URL", database_url);
    std::env::set_var(
        "AUTH__REDIS__URL",
        std::env::var("AUTH_TEST_REDIS_URL")
            .unwrap_or_else(|_| "redis://localhost:6379/8".to_string()),
    );
    std::env::set_var(
        "AUTH__SECURITY__MASTER_KEY",
        std::env::var("AUTH_TEST_MASTER_KEY")
            .unwrap_or_else(|_| "3geuNbeEwCC5OwBz78oo3fbuecUVKlNa4NmP1beftWQ=".to_string()),
    );
    std::env::set_var("AUTH__DATABASE__AUTO_MIGRATE", "true");
    std::env::set_var("AUTH__REDIS__REQUIRED", "false");
    Settings::load(None, None).expect("加载测试配置")
}

fn claims(state: &AppState) -> TokenClaims {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    TokenClaims {
        iss: state.config.issuer(),
        sub: Uuid::now_v7().to_string(),
        aud: state.access_audience().to_string(),
        exp: now + 600,
        iat: now,
        nbf: now - 1,
        jti: Uuid::now_v7().to_string(),
        tenant_id: "00000000-0000-0000-0000-000000000001".to_string(),
        client_id: "integration-test".to_string(),
        scope: "openid profile email".to_string(),
        sid: Uuid::now_v7().to_string(),
        amr: vec!["pwd".to_string()],
        acr: "urn:auth:acr:pwd".to_string(),
        typ: "access".to_string(),
        auth_time: Some(now),
        nonce: None,
        at_hash: None,
        name: Some("集成测试".to_string()),
        preferred_username: Some("integration".to_string()),
        email: Some("integration@example.com".to_string()),
        email_verified: Some(true),
        phone_number: None,
        phone_number_verified: None,
        picture: None,
    }
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL 与 Redis；设置 AUTH_TEST_DATABASE_URL 后运行"]
async fn signing_keys_persist_and_tokens_verify() {
    let state = AppState::new(test_settings())
        .await
        .expect("初始化应用状态");

    // 私钥不落明文：数据库中只是加密后的密文
    let (encrypted,): (String,) = sqlx::query_as(
        "SELECT private_key_encrypted FROM signing_keys WHERE status = 'active' LIMIT 1",
    )
    .fetch_one(&state.pool)
    .await
    .expect("读取 active 签名密钥");
    assert!(!encrypted.contains("PRIVATE KEY"));
    assert!(!encrypted.trim_start().starts_with("-----"));

    let claims = claims(&state);
    let (token, kid) = state.keys.sign(&claims).await.expect("签发 Token");
    assert_eq!(token.split('.').count(), 3);

    let verified: TokenClaims = state
        .keys
        .verify(&token, Some(state.access_audience()))
        .await
        .expect("验证 Token");
    assert_eq!(verified.sub, claims.sub);
    assert_eq!(verified.jti, claims.jti);
    assert_eq!(verified.scope, claims.scope);

    // kid 必须出现在 JWKS 中，且只包含公钥
    let jwks = state.keys.jwks().await.expect("读取 JWKS");
    let keys = jwks["keys"].as_array().expect("JWKS keys 数组");
    assert!(keys.iter().any(|key| key["kid"] == kid.as_str()));
    assert!(keys.iter().all(|key| key.get("d").is_none()));

    // 伪造 Token 必须验签失败
    let mut parts: Vec<&str> = token.split('.').collect();
    parts[2] = "AAAA";
    let tampered = parts.join(".");
    assert!(state
        .keys
        .verify::<TokenClaims>(&tampered, Some(state.access_audience()))
        .await
        .is_err());
}
