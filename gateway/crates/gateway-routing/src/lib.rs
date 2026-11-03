//! # gateway-routing
//!
//! 路由表编译与运行时匹配。
//!
//! 设计核心：
//!   1. `RouteTable::compile()` 把一组 RouteConfig 编译成不可变表，
//!      启动时编译一次，运行时只读，无锁。
//!   2. 匹配顺序严格遵守需求文档 4.2 节：
//!      Host → Path 类型（Exact > Prefix）→ Path 值 → Method → Header →
//!      Query → Priority。
//!   3. 返回值区分三种情况：
//!      - `Some(MatchedRoute)`：成功匹配
//!      - `Some(MatchedRoute::MethodNotAllowed { allowed_methods })`：Host+Path
//!        匹配但 Method 不支持 → 405
//!      - `None`：没有任何匹配 → 404
//!
//! 运行时不做任何数据库查询、不做任何 IO；所有数据在编译时已经就绪。

#![allow(clippy::needless_doctest_main)]

pub mod table;

pub use table::{MatchResult, RouteTable};
