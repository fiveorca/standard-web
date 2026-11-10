// ! ClickHouse 客户端封装
//
// 使用 clickhouse crate (官方 Rust 客户端)，通过 HTTP 协议读写。

use clickhouse::Client;
use tracing::info;

use crate::config::ClickHouseConfig;

/// 线程安全的 ClickHouse 客户端 (内部 Client 本身就是可 clone 的)
#[derive(Clone)]
pub struct ClickHouse {
    pub(crate) client: Client,
    pub database: String,
}

impl ClickHouse {
    pub fn new(cfg: &ClickHouseConfig) -> Self {
        let mut builder = Client::default().with_url(&cfg.url).with_user(&cfg.user);
        if !cfg.password.is_empty() {
            builder = builder.with_password(&cfg.password);
        }
        let client = builder.with_database(&cfg.database);
        info!(url = %cfg.url, user = %cfg.user, database = %cfg.database, "ClickHouse 客户端初始化");
        Self {
            client,
            database: cfg.database.clone(),
        }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub async fn ping(&self) -> anyhow::Result<()> {
        self.client
            .query("SELECT 1 AS ok")
            .execute()
            .await?;
        Ok(())
    }

    pub async fn exec(&self, sql: &str) -> anyhow::Result<()> {
        self.client.query(sql).execute().await?;
        Ok(())
    }
}
