// ! 分析服务

use crate::common::error::AppError;
use crate::infrastructure::clickhouse::repository::LogRepository;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct AnalyticsOverview {
    pub total_count: u64,
    pub error_count: u64,
    pub fatal_count: u64,
    pub error_rate: f64,
    pub fatal_rate: f64,
    pub levels: Vec<crate::infrastructure::clickhouse::repository::LevelCount>,
    pub services: Vec<crate::infrastructure::clickhouse::repository::ServiceCount>,
}

pub struct AnalyticsService {
    repo: Arc<LogRepository<'static>>,
}

impl AnalyticsService {
    pub fn new(repo: LogRepository<'static>) -> Self {
        Self {
            repo: Arc::new(repo),
        }
    }

    pub async fn overview(
        &self,
        tenant_id: String,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
    ) -> Result<AnalyticsOverview, AppError> {
        let overview = self
            .repo
            .overview(&tenant_id, start_time, end_time)
            .await?;
        let levels = self
            .repo
            .level_counts(&tenant_id, start_time, end_time)
            .await?;
        let services = self
            .repo
            .service_counts(&tenant_id, start_time, end_time)
            .await?;

        let total = overview.total_count.max(1);
        let error_rate = (overview.error_count as f64) / (total as f64) * 100.0;
        let fatal_rate = (overview.fatal_count as f64) / (total as f64) * 100.0;

        Ok(AnalyticsOverview {
            total_count: overview.total_count,
            error_count: overview.error_count,
            fatal_count: overview.fatal_count,
            error_rate,
            fatal_rate,
            levels,
            services,
        })
    }

    pub async fn trends(
        &self,
        tenant_id: String,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        granularity: String,
    ) -> Result<Vec<crate::infrastructure::clickhouse::repository::TrendBucket>, AppError> {
        let now = Utc::now();
        let start = start_time.unwrap_or_else(|| now - Duration::hours(24));
        let end = end_time.unwrap_or(now);
        self.repo.trends(&tenant_id, start, end, &granularity).await
    }

    pub async fn top_errors(
        &self,
        tenant_id: String,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        limit: Option<usize>,
    ) -> Result<Vec<crate::infrastructure::clickhouse::repository::TopError>, AppError> {
        self.repo
            .top_errors(&tenant_id, start_time, end_time, limit.unwrap_or(20))
            .await
    }
}
