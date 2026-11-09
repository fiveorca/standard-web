//! 用户扩展属性的定义、校验与取值。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::application::audit::{self, AuditEntry};
use crate::bootstrap::AppState;
use crate::domain::UserAttribute;
use crate::shared::{AppError, AppResult, Page, PageQuery, RequestMeta};

#[derive(Debug, Clone, Deserialize)]
pub struct AttributeInput {
    pub code: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_type")]
    pub data_type: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub default_value: Option<Value>,
    #[serde(default)]
    pub options: Vec<Value>,
    #[serde(default)]
    pub validation: Value,
    #[serde(default)]
    pub user_type: Option<String>,
    #[serde(default)]
    pub sort_order: i32,
    #[serde(default = "default_status")]
    pub status: String,
}

fn default_type() -> String {
    "string".to_string()
}

fn default_status() -> String {
    "active".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttributeValuesInput {
    #[serde(default)]
    pub values: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttributeValueView {
    pub code: String,
    pub name: String,
    pub data_type: String,
    pub value: Value,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

fn validate_definition(input: &AttributeInput) -> AppResult<()> {
    let code = input.code.trim();
    if code.len() < 2 || code.len() > 64 {
        return Err(AppError::validation("code", "属性编码长度需在 2-64 之间"));
    }
    if !code
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(AppError::validation(
            "code",
            "属性编码仅允许字母、数字、下划线、点和短横线",
        ));
    }
    if !matches!(
        input.data_type.as_str(),
        "string" | "number" | "boolean" | "date" | "enum" | "array"
    ) {
        return Err(AppError::validation("data_type", "不支持的属性类型"));
    }
    if input.data_type == "enum" && input.options.is_empty() {
        return Err(AppError::validation("options", "枚举类型必须提供可选值"));
    }
    if !matches!(input.status.as_str(), "active" | "disabled") {
        return Err(AppError::validation("status", "属性状态不合法"));
    }
    if let Some(default) = &input.default_value {
        validate_value(input, default)?;
    }
    Ok(())
}

fn validate_value(definition: &AttributeInput, value: &Value) -> AppResult<()> {
    if value.is_null() {
        return Ok(());
    }
    match definition.data_type.as_str() {
        "string" => {
            let text = value
                .as_str()
                .ok_or_else(|| AppError::validation("value", "属性值必须是字符串"))?;
            let min = definition
                .validation
                .get("min_length")
                .and_then(Value::as_u64);
            let max = definition
                .validation
                .get("max_length")
                .and_then(Value::as_u64);
            if let Some(min) = min {
                if (text.chars().count() as u64) < min {
                    return Err(AppError::validation(
                        "value",
                        format!("字符串长度不能小于 {min}"),
                    ));
                }
            }
            if let Some(max) = max {
                if (text.chars().count() as u64) > max {
                    return Err(AppError::validation(
                        "value",
                        format!("字符串长度不能大于 {max}"),
                    ));
                }
            }
            if let Some(pattern) = definition.validation.get("pattern").and_then(Value::as_str) {
                let regex = regex::Regex::new(pattern)
                    .map_err(|_| AppError::server_error("属性校验正则配置无效"))?;
                if !regex.is_match(text) {
                    return Err(AppError::validation("value", "字符串不符合格式要求"));
                }
            }
            if !definition.options.is_empty()
                && !definition
                    .options
                    .iter()
                    .any(|item| item.as_str() == Some(text))
            {
                return Err(AppError::validation("value", "取值不在允许范围内"));
            }
        }
        "number" => {
            let number = value
                .as_f64()
                .ok_or_else(|| AppError::validation("value", "属性值必须是数字"))?;
            if let Some(min) = definition.validation.get("min").and_then(Value::as_f64) {
                if number < min {
                    return Err(AppError::validation("value", format!("数值不能小于 {min}")));
                }
            }
            if let Some(max) = definition.validation.get("max").and_then(Value::as_f64) {
                if number > max {
                    return Err(AppError::validation("value", format!("数值不能大于 {max}")));
                }
            }
        }
        "boolean" => {
            value
                .as_bool()
                .ok_or_else(|| AppError::validation("value", "属性值必须是布尔值"))?;
        }
        "date" => {
            let text = value
                .as_str()
                .ok_or_else(|| AppError::validation("value", "日期必须是 YYYY-MM-DD 字符串"))?;
            chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d")
                .map_err(|_| AppError::validation("value", "日期格式应为 YYYY-MM-DD"))?;
        }
        "enum" => {
            let text = value
                .as_str()
                .ok_or_else(|| AppError::validation("value", "枚举值必须是字符串"))?;
            if !definition
                .options
                .iter()
                .any(|item| item.as_str() == Some(text))
            {
                return Err(AppError::validation("value", "枚举值不在允许范围内"));
            }
        }
        "array" => {
            let items = value
                .as_array()
                .ok_or_else(|| AppError::validation("value", "属性值必须是数组"))?;
            let max = definition
                .validation
                .get("max_items")
                .and_then(Value::as_u64)
                .unwrap_or(50);
            if items.len() as u64 > max {
                return Err(AppError::validation(
                    "value",
                    format!("数组元素不能超过 {max} 个"),
                ));
            }
            for item in items {
                let text = item
                    .as_str()
                    .ok_or_else(|| AppError::validation("value", "数组元素必须是字符串"))?;
                if !definition.options.is_empty()
                    && !definition
                        .options
                        .iter()
                        .any(|option| option.as_str() == Some(text))
                {
                    return Err(AppError::validation("value", "数组元素不在允许范围内"));
                }
            }
        }
        _ => return Err(AppError::validation("data_type", "不支持的属性类型")),
    }
    Ok(())
}

impl AppState {
    pub async fn list_attributes(
        &self,
        tenant_id: Uuid,
        page: &PageQuery,
    ) -> AppResult<Page<UserAttribute>> {
        let total: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM user_attributes WHERE tenant_id = $1 AND deleted_at IS NULL",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;
        let rows = sqlx::query_as::<_, UserAttribute>(
            "SELECT id, tenant_id, code, name, description, data_type, required, default_value,
                    options, validation, user_type, sort_order, status, created_at, updated_at,
                    deleted_at
               FROM user_attributes
              WHERE tenant_id = $1 AND deleted_at IS NULL
              ORDER BY sort_order, created_at
              LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id)
        .bind(page.limit())
        .bind(page.offset())
        .fetch_all(&self.pool)
        .await?;
        Ok(Page::new(rows, total, page))
    }

    pub async fn get_attribute(&self, tenant_id: Uuid, id: Uuid) -> AppResult<UserAttribute> {
        sqlx::query_as::<_, UserAttribute>(
            "SELECT id, tenant_id, code, name, description, data_type, required, default_value,
                    options, validation, user_type, sort_order, status, created_at, updated_at,
                    deleted_at
               FROM user_attributes WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::not_found("属性不存在"))
    }

    pub async fn create_attribute(
        &self,
        tenant_id: Uuid,
        input: &AttributeInput,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<UserAttribute> {
        validate_definition(input)?;
        let row = sqlx::query_as::<_, UserAttribute>(
            "INSERT INTO user_attributes
                (tenant_id, code, name, description, data_type, required, default_value, options,
                 validation, user_type, sort_order, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             RETURNING id, tenant_id, code, name, description, data_type, required, default_value,
                       options, validation, user_type, sort_order, status, created_at, updated_at,
                       deleted_at",
        )
        .bind(tenant_id)
        .bind(input.code.trim())
        .bind(&input.name)
        .bind(input.description.as_deref())
        .bind(&input.data_type)
        .bind(input.required)
        .bind(input.default_value.clone())
        .bind(json!(input.options))
        .bind(if input.validation.is_null() {
            json!({})
        } else {
            input.validation.clone()
        })
        .bind(input.user_type.as_deref())
        .bind(input.sort_order)
        .bind(&input.status)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| {
            if let sqlx::Error::Database(db_error) = &error {
                if db_error.code().as_deref() == Some("23505") {
                    return AppError::conflict("属性编码已存在");
                }
            }
            error.into()
        })?;
        audit::record(&self.pool, {
            let mut entry = AuditEntry::new("user.attribute.created")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("user_attribute", row.id.to_string())
                .detail(json!({ "code": row.code }));
            entry.request_context(meta);
            entry
        })
        .await?;
        Ok(row)
    }

    pub async fn update_attribute(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: &AttributeInput,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<UserAttribute> {
        validate_definition(input)?;
        self.get_attribute(tenant_id, id).await?;
        let row = sqlx::query_as::<_, UserAttribute>(
            "UPDATE user_attributes SET
                code = $3, name = $4, description = $5, data_type = $6, required = $7,
                default_value = $8, options = $9, validation = $10, user_type = $11,
                sort_order = $12, status = $13, updated_at = now()
              WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
             RETURNING id, tenant_id, code, name, description, data_type, required, default_value,
                       options, validation, user_type, sort_order, status, created_at, updated_at,
                       deleted_at",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(input.code.trim())
        .bind(&input.name)
        .bind(input.description.as_deref())
        .bind(&input.data_type)
        .bind(input.required)
        .bind(input.default_value.clone())
        .bind(json!(input.options))
        .bind(if input.validation.is_null() {
            json!({})
        } else {
            input.validation.clone()
        })
        .bind(input.user_type.as_deref())
        .bind(input.sort_order)
        .bind(&input.status)
        .fetch_one(&self.pool)
        .await?;
        audit::record(&self.pool, {
            let mut entry = AuditEntry::new("user.attribute.updated")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("user_attribute", id.to_string())
                .detail(json!({ "code": row.code }));
            entry.request_context(meta);
            entry
        })
        .await?;
        Ok(row)
    }

    pub async fn delete_attribute(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        let attribute = self.get_attribute(tenant_id, id).await?;
        sqlx::query(
            "UPDATE user_attributes SET deleted_at = now(), status = 'disabled', updated_at = now()
              WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        audit::record(&self.pool, {
            let mut entry = AuditEntry::new("user.attribute.deleted")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("user_attribute", id.to_string())
                .detail(json!({ "code": attribute.code }));
            entry.request_context(meta);
            entry
        })
        .await?;
        Ok(())
    }

    pub async fn set_user_attribute_values(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        values: &Map<String, Value>,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<Vec<AttributeValueView>> {
        self.get_user(tenant_id, user_id).await?;
        let definitions = sqlx::query_as::<_, UserAttribute>(
            "SELECT id, tenant_id, code, name, description, data_type, required, default_value,
                    options, validation, user_type, sort_order, status, created_at, updated_at,
                    deleted_at
               FROM user_attributes WHERE tenant_id = $1 AND deleted_at IS NULL",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        let by_code: HashMap<String, &UserAttribute> = definitions
            .iter()
            .map(|item| (item.code.to_ascii_lowercase(), item))
            .collect();

        let mut tx = self.pool.begin().await?;
        for (code, value) in values {
            let definition = by_code
                .get(&code.to_ascii_lowercase())
                .ok_or_else(|| AppError::validation("code", format!("未定义的扩展属性: {code}")))?;
            let input = AttributeInput {
                code: definition.code.clone(),
                name: definition.name.clone(),
                description: definition.description.clone(),
                data_type: definition.data_type.clone(),
                required: definition.required,
                default_value: definition.default_value.clone(),
                options: definition.options.as_array().cloned().unwrap_or_default(),
                validation: definition.validation.clone(),
                user_type: definition.user_type.clone(),
                sort_order: definition.sort_order,
                status: definition.status.clone(),
            };
            validate_value(&input, value)?;
            sqlx::query(
                "INSERT INTO user_attribute_values (user_id, attribute_id, tenant_id, value)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (user_id, attribute_id)
                 DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
            )
            .bind(user_id)
            .bind(definition.id)
            .bind(tenant_id)
            .bind(value)
            .execute(&mut *tx)
            .await?;
        }

        for definition in &definitions {
            if !definition.required {
                continue;
            }
            let provided = values
                .keys()
                .any(|code| code.eq_ignore_ascii_case(&definition.code));
            if provided {
                continue;
            }
            let existing: Option<(i64,)> = sqlx::query_as(
                "SELECT 1::bigint FROM user_attribute_values
                  WHERE user_id = $1 AND attribute_id = $2",
            )
            .bind(user_id)
            .bind(definition.id)
            .fetch_optional(&mut *tx)
            .await?;
            if existing.is_none() {
                return Err(AppError::validation(
                    "values",
                    format!("必填属性缺失: {}", definition.code),
                ));
            }
        }

        audit::record_in_tx(&mut tx, {
            let mut entry = AuditEntry::new("user.attributes.updated")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("user", user_id.to_string())
                .detail(json!({ "codes": values.keys().cloned().collect::<Vec<_>>() }));
            entry.request_context(meta);
            entry
        })
        .await?;
        tx.commit().await?;
        self.list_user_attribute_values(tenant_id, user_id).await
    }

    pub async fn list_user_attribute_values(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<Vec<AttributeValueView>> {
        let rows: Vec<(String, String, String, Value, chrono::DateTime<chrono::Utc>)> =
            sqlx::query_as(
                "SELECT a.code, a.name, a.data_type, v.value, v.updated_at
               FROM user_attribute_values v
               JOIN user_attributes a ON a.id = v.attribute_id
              WHERE v.user_id = $1 AND v.tenant_id = $2 AND a.deleted_at IS NULL
              ORDER BY a.sort_order, a.code",
            )
            .bind(user_id)
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| AttributeValueView {
                code: row.0,
                name: row.1,
                data_type: row.2,
                value: row.3,
                updated_at: row.4,
            })
            .collect())
    }
}
