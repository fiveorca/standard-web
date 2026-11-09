//! 应用服务层。

pub mod attributes;
pub mod audit;
pub mod contacts;
pub mod groups;
pub mod orgs;
pub mod registrations;
pub mod users;

pub use contacts::ContactsView;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::{User, UserProfile};
use crate::shared::AppResult;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProfileInput {
    #[serde(default)]
    pub gender: Option<String>,
    #[serde(default)]
    pub birthday: Option<NaiveDate>,
    #[serde(default)]
    pub bio: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub locale: Option<String>,
    #[serde(default)]
    pub website: Option<String>,
    #[serde(default)]
    pub company: Option<String>,
    #[serde(default)]
    pub job_title: Option<String>,
    #[serde(default)]
    pub extra: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserView {
    #[serde(flatten)]
    pub user: User,
    pub profile: Option<UserProfile>,
    pub tags: Vec<String>,
}

/// 计算资料完整度（0-100）。
pub fn completeness(user: &User, profile: Option<&UserProfile>) -> i16 {
    let mut filled = 0_i16;
    let mut total = 0_i16;
    let mut check = |value: bool| {
        total += 1;
        if value {
            filled += 1;
        }
    };
    check(
        user.display_name
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty()),
    );
    check(
        user.avatar_url
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty()),
    );
    check(user.email.is_some());
    check(user.phone.is_some());
    if let Some(profile) = profile {
        check(profile.gender.is_some());
        check(profile.birthday.is_some());
        check(
            profile
                .bio
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
        );
        check(
            profile
                .region
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
        );
        check(profile.timezone.is_some());
        check(profile.locale.is_some());
    } else {
        total += 6;
    }
    if total == 0 {
        return 0;
    }
    (filled * 100 / total) as i16
}

pub async fn load_profile(
    state: &crate::bootstrap::AppState,
    user_id: uuid::Uuid,
) -> AppResult<Option<UserProfile>> {
    let profile = sqlx::query_as::<_, UserProfile>(
        "SELECT user_id, gender, birthday, bio, region, timezone, locale, website,
                company, job_title, extra, completeness, created_at, updated_at
           FROM user_profiles WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    Ok(profile)
}
