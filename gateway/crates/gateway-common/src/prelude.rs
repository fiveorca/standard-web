//! prelude —— 常用类型的统一 re-export。
//!
//! 下游 crate 可以用 `use gateway_common::prelude::*;` 一次性引入所有
//! 常用类型，避免在每个文件中写多行 import。
//!
//! 这个模块只做 re-export，不定义任何新类型。

pub use crate::error::{ErrorCode, ErrorResponse, GatewayError};
pub use crate::request_id::RequestId;
