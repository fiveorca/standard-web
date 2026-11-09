//! 用户中心集成测试。
//!
//! 需要真实 PostgreSQL 与认证中心（创建带密码的身份时才会调用认证中心）。
//! 运行方式：
//!
//! ```bash
//! USER_TEST_DATABASE_URL='postgres://user_center:user_center@localhost:5432/user_center_test' \
//! USER_TEST_REDIS_URL='redis://localhost:6379/9' \
//! USER_TEST_AUTH_BASE_URL='http://localhost:8080' \
//! USER_TEST_INTERNAL_TOKEN='dev-internal-token-change-me-0001' \
//! cargo test --test integration -- --ignored --test-threads=1
//! ```
//!
//! 测试会真实执行 Migration，并对数据库进行读写。

use serde_json::json;
use uuid::Uuid;

use user_center::application::groups::GroupInput;
use user_center::application::users::{CreateUserInput, UserListQuery};
use user_center::bootstrap::AppState;
use user_center::config::Settings;
use user_center::infrastructure::outbox;
use user_center::shared::{RequestMeta, DEFAULT_TENANT_ID};

fn test_settings() -> Settings {
    let database_url = std::env::var("USER_TEST_DATABASE_URL")
        .expect("必须设置 USER_TEST_DATABASE_URL 指向可写的测试数据库");
    let mut settings = Settings::default();
    settings.server.bind = "127.0.0.1:0".to_string();
    settings.database.url = database_url;
    settings.database.auto_migrate = true;
    settings.database.max_connections = 4;
    settings.database.min_connections = 1;
    settings.redis.url = std::env::var("USER_TEST_REDIS_URL")
        .unwrap_or_else(|_| "redis://localhost:6379/9".to_string());
    settings.redis.required = false;
    settings.redis.key_prefix = "user-center-test".to_string();
    settings.auth.base_url = std::env::var("USER_TEST_AUTH_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:8080".to_string());
    settings.auth.internal_token = std::env::var("USER_TEST_INTERNAL_TOKEN")
        .unwrap_or_else(|_| "dev-internal-token-change-me-0001".to_string());
    settings.auth.issuer = settings.auth.base_url.clone();
    settings.auth.audience = format!("{}/api", settings.auth.base_url.trim_end_matches('/'));
    settings
}

fn sample_user(id: Uuid, tenant_id: Uuid) -> CreateUserInput {
    let username = format!("it_{}", &id.simple().to_string()[..16]);
    CreateUserInput {
        id: Some(id),
        tenant_id,
        username: username.clone(),
        email: Some(format!("{username}@example.com")),
        phone: None,
        password: None,
        display_name: Some("集成测试用户".to_string()),
        avatar_url: None,
        status: Some("active".to_string()),
        source: Some("integration".to_string()),
        remark: Some("integration-test".to_string()),
        tags: vec!["integration".to_string()],
        profile: None,
        email_verified: true,
        phone_verified: false,
    }
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL；设置 USER_TEST_DATABASE_URL 后运行"]
async fn user_lifecycle_status_and_tenant_isolation() {
    let state = AppState::new(test_settings())
        .await
        .expect("初始化应用状态");
    let tenant = DEFAULT_TENANT_ID;
    let meta = RequestMeta::default();

    let id = Uuid::now_v7();
    let input = sample_user(id, tenant);
    let user = state
        .create_user(input.clone(), None, &meta)
        .await
        .expect("创建用户");
    assert_eq!(user.id, id);
    assert_eq!(user.tenant_id, tenant);

    // 唯一约束：重复创建必须失败
    assert!(state.create_user(input, None, &meta).await.is_err());

    let view = state.get_user_view(tenant, id).await.expect("查询用户详情");
    assert_eq!(view.user.id, id);
    assert_eq!(view.tags, vec!["integration".to_string()]);

    // 分页与关键字搜索
    let page = state
        .list_users(
            tenant,
            &UserListQuery {
                page: Some(1),
                page_size: Some(10),
                keyword: Some(view.user.username.clone()),
                ..Default::default()
            },
        )
        .await
        .expect("用户分页");
    assert!(page.items.iter().any(|item| item.user.id == id));

    // 跨租户隔离：其他租户不可见
    let other_tenant = Uuid::now_v7();
    assert!(state.get_user_view(other_tenant, id).await.is_err());

    // 状态变更与历史
    let updated = state
        .change_status(tenant, id, "locked", Some("integration"), None, &meta)
        .await
        .expect("变更状态");
    assert_eq!(updated.status, "locked");
    let history = state
        .list_status_history(tenant, id)
        .await
        .expect("状态历史");
    assert!(history.iter().any(|item| item.to_status == "locked"));

    // 分组创建、加入、查询、退出
    let group = state
        .create_group(
            tenant,
            &GroupInput {
                parent_id: None,
                code: format!("g{}", &id.simple().to_string()[..10]),
                name: "集成分组".to_string(),
                description: None,
                status: "active".to_string(),
                tags: vec![],
                extra: json!({}),
                sort_order: 0,
            },
            None,
            &meta,
        )
        .await
        .expect("创建分组");
    let added = state
        .add_group_members(tenant, group.id, &[id], None, &meta)
        .await
        .expect("加入分组");
    assert_eq!(added, 1);
    let groups = state.list_user_groups(tenant, id).await.expect("用户分组");
    assert!(groups.iter().any(|item| item.id == group.id));
    let removed = state
        .remove_group_members(tenant, group.id, &[id], None, &meta)
        .await
        .expect("退出分组");
    assert_eq!(removed, 1);

    // 软删除后不可查询，恢复后可查询
    state
        .delete_user(tenant, id, Some("integration"), None, &meta)
        .await
        .expect("删除用户");
    assert!(state.get_user_view(tenant, id).await.is_err());
    state
        .restore_user(tenant, id, None, &meta)
        .await
        .expect("恢复用户");
    assert!(state.get_user_view(tenant, id).await.is_ok());

    // 清理
    let _ = state.delete_group(tenant, group.id, None, &meta).await;
    let _ = state
        .delete_user(tenant, id, Some("cleanup"), None, &meta)
        .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL；设置 USER_TEST_DATABASE_URL 后运行"]
async fn inbox_is_idempotent() {
    let state = AppState::new(test_settings())
        .await
        .expect("初始化应用状态");
    let event_id = Uuid::now_v7();
    let payload = json!({ "tenant_id": DEFAULT_TENANT_ID, "identity_id": Uuid::now_v7() });
    let first = outbox::inbox_accept(
        &state.pool,
        "integration-test",
        event_id,
        "auth.identity.activated",
        &payload,
    )
    .await
    .expect("首次消费");
    let second = outbox::inbox_accept(
        &state.pool,
        "integration-test",
        event_id,
        "auth.identity.activated",
        &payload,
    )
    .await
    .expect("重复消费");
    assert!(first);
    assert!(!second);
}
