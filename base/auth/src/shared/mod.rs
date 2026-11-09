//! 共享模块：错误、响应、工具。

pub mod error;
pub mod response;
pub mod util;

pub use error::{AppError, AppResult};
pub use response::{ok, ApiResponse, Page, PageQuery};
pub use util::*;
