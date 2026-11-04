//! 插件执行阶段。
//!
//! 对应设计文档 4.12 规定的 9 个阶段。阶段的**先后顺序即枚举的声明顺序**，
//! 借助 `#[derive(PartialOrd, Ord)]` 可以直接用于排序与比较。
//!
//! ```text
//! 请求方向                                   响应方向
//! ─────────────────────────────────────────────────────────
//! RequestPreRoute     路由匹配前            UpstreamResponse   上游响应到达后
//! RequestPostRoute    路由匹配后            ResponsePreClient  响应返回客户端前
//! Authentication      认证                  AccessLog          访问日志输出时
//! Authorization       授权
//! RequestPreUpstream  转发上游前
//! UpstreamSelection   上游选择
//! ```
//!
//! # 为什么阶段是强类型枚举而不是字符串
//!
//! 字符串阶段名在编译期无法校验，写错一个字母就静默失效——对安全插件
//! （Authentication）尤为危险。枚举保证阶段只能在编译期确定的集合内取值，
//! 同时支持 `serde` 反序列化（Phase 3 动态插件配置需要）。

use serde::{Deserialize, Serialize};

/// 插件执行阶段。
///
/// 派生 `Ord` 的排序结果与声明顺序一致，因此可以安全地用它做
/// "按 Pipeline 顺序执行"的比较。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginPhase {
    /// 路由匹配之前：只能看到原始请求（method/uri/headers），尚无 Route。
    ///
    /// 典型插件：Request ID 生成、Trace Context 提取、全局 CORS 预检。
    RequestPreRoute,

    /// 路由匹配之后、认证之前：可以读取 `RouteConfig` 做按路由的策略决策。
    ///
    /// 典型插件：按路由生效的限流、按路由的 Header 转换。
    RequestPostRoute,

    /// 认证阶段：验证调用者身份。
    ///
    /// 典型插件：JWT、API Key、Basic、IP 黑白名单。
    /// 此阶段失败必须短路（401/403），不得继续进入上游。
    Authentication,

    /// 授权阶段：确认已认证身份是否有权限访问该路由/资源。
    Authorization,

    /// 转发上游之前的最后一道请求加工阶段。
    ///
    /// 典型插件：请求 Header 重写、请求体验证、注入代理链头。
    RequestPreUpstream,

    /// 上游端点选择阶段。
    ///
    /// 典型插件：灰度/金丝雀（按权重改写选中端点）、熔断器状态检查。
    UpstreamSelection,

    /// 上游响应头已到达、响应体尚未开始回传的阶段。
    ///
    /// 典型插件：熔断器成功/失败记账、响应 Header 转换。
    UpstreamResponse,

    /// 响应返回客户端之前的最后加工阶段。
    ///
    /// 典型插件：CORS 响应头、压缩、响应 Header 清理。
    ResponsePreClient,

    /// 访问日志输出阶段。
    ///
    /// 典型插件：Metrics 统计、AccessLog 结构化输出。
    AccessLog,
}

impl PluginPhase {
    /// 全部阶段，按 Pipeline 执行顺序排列。
    ///
    /// 用于遍历/注册完整性检查（例如启动时确认每个阶段都有对应处理）。
    pub const ALL: [PluginPhase; 9] = [
        PluginPhase::RequestPreRoute,
        PluginPhase::RequestPostRoute,
        PluginPhase::Authentication,
        PluginPhase::Authorization,
        PluginPhase::RequestPreUpstream,
        PluginPhase::UpstreamSelection,
        PluginPhase::UpstreamResponse,
        PluginPhase::ResponsePreClient,
        PluginPhase::AccessLog,
    ];

    /// 稳定的字符串表示，用于日志、指标标签与管理接口。
    ///
    /// 与 `serde` 的 `snake_case` 命名保持一致，
    /// 避免日志里的阶段名与配置里的阶段名出现两套写法。
    pub fn as_str(self) -> &'static str {
        match self {
            PluginPhase::RequestPreRoute => "request_pre_route",
            PluginPhase::RequestPostRoute => "request_post_route",
            PluginPhase::Authentication => "authentication",
            PluginPhase::Authorization => "authorization",
            PluginPhase::RequestPreUpstream => "request_pre_upstream",
            PluginPhase::UpstreamSelection => "upstream_selection",
            PluginPhase::UpstreamResponse => "upstream_response",
            PluginPhase::ResponsePreClient => "response_pre_client",
            PluginPhase::AccessLog => "access_log",
        }
    }

    /// 是否属于"请求方向"阶段（此时还没有上游响应）。
    ///
    /// 请求方向阶段禁止访问 `PluginContext::response`：
    /// 那些字段此时必定是 `None`，用于在 P2.3+ 实现中提前发现误用。
    pub fn is_request_side(self) -> bool {
        matches!(
            self,
            PluginPhase::RequestPreRoute
                | PluginPhase::RequestPostRoute
                | PluginPhase::Authentication
                | PluginPhase::Authorization
                | PluginPhase::RequestPreUpstream
                | PluginPhase::UpstreamSelection
        )
    }

    /// 是否属于"响应方向"阶段（此时已拿到上游响应或正在输出日志）。
    pub fn is_response_side(self) -> bool {
        !self.is_request_side()
    }
}

impl std::fmt::Display for PluginPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 直接复用 as_str，保证 Display 与 serde/日志的命名一致
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 枚举声明顺序即 Pipeline 顺序（Ord 派生依赖此约定）
    #[test]
    fn declaration_order_matches_pipeline_order() {
        let mut phases = PluginPhase::ALL;
        phases.sort();
        assert_eq!(phases, PluginPhase::ALL);
    }

    /// 请求方向 / 响应方向划分正确
    #[test]
    fn request_response_side_classification() {
        assert!(PluginPhase::Authentication.is_request_side());
        assert!(!PluginPhase::Authentication.is_response_side());
        assert!(PluginPhase::ResponsePreClient.is_response_side());
        assert!(PluginPhase::AccessLog.is_response_side());
    }

    /// serde 命名与 as_str 一致
    #[test]
    fn serde_name_matches_as_str() {
        let json = serde_json::to_string(&PluginPhase::RequestPreUpstream);
        assert_eq!(json.unwrap_or_default(), "\"request_pre_upstream\"");
        assert_eq!(PluginPhase::RequestPreUpstream.as_str(), "request_pre_upstream");
    }
}
