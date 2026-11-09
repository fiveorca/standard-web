//! 统一成功响应与分页结构。

use axum::Json;
use serde::{Deserialize, Serialize};

/// 统一成功响应包装。
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub code: &'static str,
    pub data: T,
}

pub fn ok<T: Serialize>(data: T) -> Json<ApiResponse<T>> {
    Json(ApiResponse { code: "ok", data })
}

pub fn empty() -> Json<ApiResponse<serde_json::Value>> {
    ok(serde_json::json!({}))
}

/// 分页查询参数。
#[derive(Debug, Clone, Deserialize)]
pub struct PageQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

impl PageQuery {
    pub fn page(&self) -> u32 {
        self.page.unwrap_or(1).max(1)
    }

    pub fn page_size(&self) -> u32 {
        self.page_size.unwrap_or(20).clamp(1, 200)
    }

    pub fn offset(&self) -> i64 {
        i64::from((self.page() - 1) * self.page_size())
    }

    pub fn limit(&self) -> i64 {
        i64::from(self.page_size())
    }
}

impl Default for PageQuery {
    fn default() -> Self {
        Self {
            page: Some(1),
            page_size: Some(20),
        }
    }
}

/// 分页结果。
#[derive(Debug, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub page: u32,
    pub page_size: u32,
    pub total: i64,
}

impl<T> Page<T> {
    pub fn new(items: Vec<T>, total: i64, query: &PageQuery) -> Self {
        Self {
            items,
            page: query.page(),
            page_size: query.page_size(),
            total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_query_caps_page_size() {
        let query = PageQuery {
            page: Some(0),
            page_size: Some(10_000),
        };
        assert_eq!(query.page(), 1);
        assert_eq!(query.page_size(), 200);
        assert_eq!(query.offset(), 0);
    }
}
