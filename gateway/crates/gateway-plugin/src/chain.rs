//! 插件链与注册表。
//!
//! # 确定性执行顺序
//!
//! 同一阶段的插件按 `(priority, name)` **升序**排序：
//!   1. `priority` 数值小的先执行（安全插件用 10，业务插件用默认 100）
//!   2. `priority` 相同时按插件名字典序，避免 HashSet 迭代顺序带来的不确定性
//!
//! 这一约定保证：**同样的配置在任何进程、任何时刻都产生同样的执行顺序**，
//! 这对安全审计（"认证一定在限流之前还是之后"）至关重要。
//!
//! # 短路传播
//!
//! ```text
//! chain.run(ctx)
//!   ├── plugin A → Continue
//!   ├── plugin B → Continue
//!   ├── plugin C → ShortCircuit(429)   ← 立即返回，D/E/F 不再执行
//!   └── plugin D ... (未执行)
//! ```
//!
//! # 错误传播
//!
//! 任一插件返回 `Err`，整条链立即返回该错误（**fail closed**）：
//! 不会出现"某个插件出错就跳过它继续放行"的静默降级。

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::PluginError;
use crate::phase::PluginPhase;
use crate::plugin::{Plugin, PluginContext, PluginDecision};

// ---------------------------------------------------------------------------
// PluginChain
// ---------------------------------------------------------------------------

/// 一条按确定性顺序排列的插件执行链。
///
/// 通常由 [`PluginRegistry::chain_for_phase`] 产出：
/// 同一阶段的插件在启动时一次性排序，请求路径上不再做排序操作。
#[derive(Clone, Default)]
pub struct PluginChain {
    /// 已排序的插件列表（不可变）。
    ///
    /// 排序键：`(priority 升序, name 升序)`
    plugins: Vec<Arc<dyn Plugin>>,
}

impl PluginChain {
    /// 构造插件链并完成排序。
    ///
    /// 参数：
    /// - `plugins`：同阶段（或跨阶段，按调用方决定）的插件集合
    ///
    /// 排序保证确定性；重复名字的检测由 [`PluginRegistry::register`] 完成
    /// （`PluginChain` 直接接收 `Arc`，不做重名校验以免重复开销）。
    pub fn new(mut plugins: Vec<Arc<dyn Plugin>>) -> Self {
        // `sort_by` 是稳定排序；比较键为 (priority, name)
        plugins.sort_by(|a, b| {
            // 先比优先级（小者先执行）
            a.priority()
                .cmp(&b.priority())
                // 同优先级再比名字（字典序升序）
                .then_with(|| a.name().cmp(b.name()))
        });
        Self { plugins }
    }

    /// 链中插件数量。
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// 是否为空链（空链 `run` 直接返回 `Continue`）。
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// 插件名称列表（按执行顺序），用于日志与启动自检。
    pub fn names(&self) -> Vec<&'static str> {
        self.plugins.iter().map(|p| p.name()).collect()
    }

    /// 执行整条链。
    ///
    /// 参数：
    /// - `ctx`：本阶段可用的插件上下文
    ///
    /// 返回：
    /// - `Ok(PluginDecision::Continue)`：全部插件都放行
    /// - `Ok(PluginDecision::ShortCircuit(resp))`：某个插件短路
    /// - `Err(PluginError)`：某个插件出错或超时
    ///
    /// # 超时实施
    /// 每个插件可声明自身超时（`Plugin::timeout`）。声明了就包一层
    /// `tokio::time::timeout`；未声明则不额外计时（避免无谓的 timer 开销）。
    pub async fn run(&self, ctx: &mut PluginContext<'_>) -> Result<PluginDecision, PluginError> {
        for plugin in &self.plugins {
            let decision = match plugin.timeout() {
                // 有声明超时：执行包在 timeout 内
                Some(limit) => match tokio::time::timeout(limit, plugin.execute(ctx)).await {
                    // 正常完成（可能是 Continue，也可能是 ShortCircuit 或 Err）
                    Ok(result) => result?,
                    // 超时：该错误会短路整条链，由 Runtime 映射为 500
                    Err(_elapsed) => {
                        return Err(PluginError::Timeout {
                            plugin: plugin.name().to_string(),
                            // `as_millis` 返回 u128，转换为 u64 用于日志；
                            // 超时阈值实际远小于 u64::MAX，转换安全
                            timeout_ms: limit.as_millis() as u64,
                        });
                    },
                },
                // 未声明超时：直接 await
                None => plugin.execute(ctx).await?,
            };

            match decision {
                // 放行：继续下一个插件
                PluginDecision::Continue => continue,
                // 短路：立即返回，后续插件与 Pipeline 全部停止
                short_circuit => {
                    tracing::debug!(
                        target: "plugin",
                        phase = %plugin.phase(),
                        plugin = plugin.name(),
                        "plugin short-circuited the request"
                    );
                    return Ok(short_circuit);
                },
            }
        }

        // 全部放行
        Ok(PluginDecision::Continue)
    }

    /// 以 `&self` 只读方式遍历插件（管理接口/自检用）。
    pub fn plugins(&self) -> &[Arc<dyn Plugin>] {
        &self.plugins
    }
}

// ---------------------------------------------------------------------------
// PluginRegistry
// ---------------------------------------------------------------------------

/// 编译期注册的插件注册表。
///
/// 对应设计文档 4.12："第一阶段使用编译时注册的内置插件，
/// 不实施未经隔离的 Rust `.so` 热加载。"
///
/// # 使用流程
/// ```text
/// let mut registry = PluginRegistry::new();
/// registry.register(Arc::new(JwtPlugin::new(cfg)))?;   // 注册（重名即失败）
/// registry.init_all().await?;                          // 初始化（失败阻止启动）
/// let chain = registry.chain_for_phase(PluginPhase::Authentication);
/// chain.run(&mut ctx).await?;                          // 请求路径上执行
/// ```
#[derive(Default)]
pub struct PluginRegistry {
    /// 名称 → 插件实例。
    ///
    /// 用 `&'static str` 作为键：插件名是编译期常量，避免 String 分配。
    plugins: HashMap<&'static str, Arc<dyn Plugin>>,
}

impl PluginRegistry {
    /// 创建空注册表。
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    /// 注册一个插件。
    ///
    /// 参数：
    /// - `plugin`：插件实例（`Arc` 便于在注册表与插件链之间共享）
    ///
    /// 返回：
    /// - `Ok(())`：注册成功
    /// - `Err(PluginError::DuplicateName)`：同名插件已存在
    ///
    /// # 为什么重名必须拒绝
    /// 插件名是确定性排序的第二排序键。若允许重名，排序结果稳定但
    /// 无法区分"哪个插件真正执行"，安全审计与日志都会失去意义。
    pub fn register(&mut self, plugin: Arc<dyn Plugin>) -> Result<(), PluginError> {
        let name = plugin.name();
        if self.plugins.contains_key(name) {
            return Err(PluginError::DuplicateName {
                name: name.to_string(),
            });
        }
        // insert 返回旧值；上面已确认不存在，因此这里必然返回 None
        self.plugins.insert(name, plugin);
        Ok(())
    }

    /// 按名称查找插件。
    pub fn get(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        self.plugins.get(name).cloned()
    }

    /// 已注册插件数量。
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// 是否为空注册表。
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// 构造指定阶段的插件链（已按 `(priority, name)` 排序）。
    ///
    /// 参数：
    /// - `phase`：目标阶段。只有 `phase()` 与该阶段相同的插件会被选中。
    ///
    /// 说明：`HashMap` 迭代顺序不确定，但 `PluginChain::new` 会做完整排序，
    /// 因此最终顺序与迭代顺序无关——这正是排序键里要包含 name 的原因。
    pub fn chain_for_phase(&self, phase: PluginPhase) -> PluginChain {
        let selected: Vec<Arc<dyn Plugin>> = self
            .plugins
            .values()
            // 只保留同阶段插件
            .filter(|p| p.phase() == phase)
            // clone Arc（+1 引用计数，无堆分配）
            .cloned()
            .collect();
        PluginChain::new(selected)
    }

    /// 初始化全部插件。
    ///
    /// 在网关接流量之前调用；任一插件返回 `Err` 都会阻止启动
    /// （fail closed：宁可启动失败，也不要带着半初始化的安全插件跑）。
    ///
    /// 遍历顺序不影响初始化结果——插件之间不应有初始化依赖。
    pub async fn init_all(&self) -> Result<(), PluginError> {
        for plugin in self.plugins.values() {
            plugin.init().await?;
            tracing::debug!(
                target: "plugin",
                name = plugin.name(),
                version = plugin.version(),
                phase = %plugin.phase(),
                "plugin initialized"
            );
        }
        Ok(())
    }

    /// 关闭全部插件（优雅关闭阶段调用）。
    ///
    /// 这里不传播错误：关闭阶段的失败只记录日志，
    /// 不应阻止进程退出。
    pub async fn shutdown_all(&self) {
        for plugin in self.plugins.values() {
            plugin.shutdown().await;
        }
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    use gateway_common::RequestId;
    use gateway_core::RequestContext;
    use http::{HeaderMap, Method, StatusCode, Uri};

    use super::*;
    use crate::plugin::{PluginContext, PluginResponse};

    /// 测试用插件：记录执行顺序，可选短路 / 可选报错 / 可选超时。
    struct TestPlugin {
        /// 插件名（同时用作执行顺序记录值）
        name: &'static str,
        /// 所属阶段
        phase: PluginPhase,
        /// 优先级
        priority: i32,
        /// 执行记录（共享给测试断言）
        log: Arc<Mutex<Vec<&'static str>>>,
        /// 是否短路
        short_circuit: bool,
        /// 是否返回错误
        fail: bool,
        /// 执行睡眠时长（用于超时测试）
        sleep: Option<Duration>,
    }

    impl TestPlugin {
        /// 构造一个默认"放行"的测试插件
        fn new(
            name: &'static str,
            phase: PluginPhase,
            priority: i32,
            log: Arc<Mutex<Vec<&'static str>>>,
        ) -> Self {
            Self {
                name,
                phase,
                priority,
                log,
                short_circuit: false,
                fail: false,
                sleep: None,
            }
        }
    }

    #[async_trait::async_trait]
    impl Plugin for TestPlugin {
        fn name(&self) -> &'static str {
            self.name
        }

        fn phase(&self) -> PluginPhase {
            self.phase
        }

        fn priority(&self) -> i32 {
            self.priority
        }

        fn timeout(&self) -> Option<Duration> {
            // sleep 存在时声明略大于 sleep 的超时，由测试用 sleep 触发
            self.sleep.map(|d| d + Duration::from_millis(10))
        }

        async fn execute(
            &self,
            ctx: &mut PluginContext<'_>,
        ) -> Result<PluginDecision, PluginError> {
            // 记录执行顺序
            if let Ok(mut guard) = self.log.lock() {
                guard.push(self.name);
            }
            // 模拟耗时（用于超时测试）
            if let Some(d) = self.sleep {
                tokio::time::sleep(d).await;
            }
            if self.fail {
                return Err(PluginError::ExecutionFailed {
                    plugin: self.name.to_string(),
                    message: "boom".into(),
                });
            }
            if self.short_circuit {
                // 短路响应：带上 request_id，验证上下文可被插件读取
                return Ok(PluginDecision::ShortCircuit(PluginResponse::from_error(
                    StatusCode::UNAUTHORIZED,
                    "GATEWAY_AUTHENTICATION_FAILED",
                    "denied",
                    Some(ctx.request_id()),
                )));
            }
            Ok(PluginDecision::Continue)
        }
    }

    /// 构造一个空请求上下文（Parts + RequestContext）
    fn make_parts() -> http::request::Parts {
        http::Request::builder()
            .method(Method::GET)
            .uri(Uri::from_static("/api/hello"))
            .body(())
            .map(|r| r.into_parts().0)
            .unwrap_or_else(|_| {
                // 构造失败属于测试代码本身写错；用空 builder 兜底避免 panic
                http::Request::new(()).into_parts().0
            })
    }

    /// 按优先级升序执行（数值小者先），同优先级按名称排序
    #[tokio::test]
    async fn chain_runs_in_priority_then_name_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let chain = PluginChain::new(vec![
            // priority 100，名字 z → 最后执行
            Arc::new(TestPlugin::new(
                "zeta",
                PluginPhase::Authentication,
                100,
                log.clone(),
            )),
            // priority 10，名字 b
            Arc::new(TestPlugin::new(
                "beta",
                PluginPhase::Authentication,
                10,
                log.clone(),
            )),
            // priority 10，名字 a → 最先执行
            Arc::new(TestPlugin::new(
                "alpha",
                PluginPhase::Authentication,
                10,
                log.clone(),
            )),
        ]);

        let mut parts = make_parts();
        let mut ctx = RequestContext::new(RequestId::new());
        let mut pctx = PluginContext::new(&mut parts, &mut ctx, None, None);
        let decision = chain.run(&mut pctx).await.expect("should not fail");
        assert!(decision.is_continue());

        let order = log.lock().expect("lock").clone();
        assert_eq!(order, vec!["alpha", "beta", "zeta"]);
    }

    /// 短路后，后续插件不再执行
    #[tokio::test]
    async fn short_circuit_stops_later_plugins() {
        let log = Arc::new(Mutex::new(Vec::new()));

        let mut blocker = TestPlugin::new(
            "deny",
            PluginPhase::Authentication,
            10,
            log.clone(),
        );
        blocker.short_circuit = true;

        let chain = PluginChain::new(vec![
            Arc::new(blocker),
            Arc::new(TestPlugin::new(
                "after",
                PluginPhase::Authentication,
                20,
                log.clone(),
            )),
        ]);

        let mut parts = make_parts();
        let mut ctx = RequestContext::new(RequestId::new());
        let mut pctx = PluginContext::new(&mut parts, &mut ctx, None, None);
        let decision = chain.run(&mut pctx).await.expect("no error");

        let resp = decision.into_response().expect("should short circuit");
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
        // 只有 deny 执行过
        let order = log.lock().expect("lock").clone();
        assert_eq!(order, vec!["deny"]);
    }

    /// 插件返回错误时整条链 fail closed
    #[tokio::test]
    async fn plugin_error_aborts_chain() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut failing =
            TestPlugin::new("broken", PluginPhase::Authentication, 10, log.clone());
        failing.fail = true;

        let chain = PluginChain::new(vec![
            Arc::new(failing),
            Arc::new(TestPlugin::new(
                "never",
                PluginPhase::Authentication,
                20,
                log.clone(),
            )),
        ]);

        let mut parts = make_parts();
        let mut ctx = RequestContext::new(RequestId::new());
        let mut pctx = PluginContext::new(&mut parts, &mut ctx, None, None);
        let err = chain.run(&mut pctx).await.expect_err("should fail");
        assert!(matches!(err, PluginError::ExecutionFailed { .. }));
        assert_eq!(log.lock().expect("lock").clone(), vec!["broken"]);
    }

    /// 注册表拒绝重名插件
    #[tokio::test]
    async fn registry_rejects_duplicate_name() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut registry = PluginRegistry::new();
        registry
            .register(Arc::new(TestPlugin::new(
                "dup",
                PluginPhase::Authentication,
                10,
                log.clone(),
            )))
            .expect("first register should succeed");

        let err = registry
            .register(Arc::new(TestPlugin::new(
                "dup",
                PluginPhase::Authentication,
                10,
                log,
            )))
            .expect_err("second register should fail");
        assert!(matches!(err, PluginError::DuplicateName { .. }));
    }

    /// 注册表按阶段筛选插件
    #[tokio::test]
    async fn registry_chain_for_phase_filters() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut registry = PluginRegistry::new();
        registry
            .register(Arc::new(TestPlugin::new(
                "auth",
                PluginPhase::Authentication,
                10,
                log.clone(),
            )))
            .expect("register auth");
        registry
            .register(Arc::new(TestPlugin::new(
                "cors",
                PluginPhase::ResponsePreClient,
                20,
                log,
            )))
            .expect("register cors");

        let chain = registry.chain_for_phase(PluginPhase::Authentication);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.names(), vec!["auth"]);

        // 没有插件的阶段返回空链
        let empty = registry.chain_for_phase(PluginPhase::AccessLog);
        assert!(empty.is_empty());
    }

    /// 空链执行直接放行
    #[tokio::test]
    async fn empty_chain_returns_continue() {
        let chain = PluginChain::new(vec![]);
        let mut parts = make_parts();
        let mut ctx = RequestContext::new(RequestId::new());
        let mut pctx = PluginContext::new(&mut parts, &mut ctx, None, None);
        assert!(chain
            .run(&mut pctx)
            .await
            .expect("empty chain")
            .is_continue());
    }

    /// 响应方向插件可以修改响应头；请求方向拿不到 response
    #[tokio::test]
    async fn response_parts_accessible_only_in_response_phase() {
        let mut parts = make_parts();
        let mut ctx = RequestContext::new(RequestId::new());

        // 请求方向：response 为 None
        {
            let mut pctx = PluginContext::new(&mut parts, &mut ctx, None, None);
            assert!(pctx.response_mut().is_none());
        }

        // 响应方向：可写
        let mut resp = crate::plugin::ResponseParts::new(StatusCode::OK, HeaderMap::new());
        {
            let mut pctx = PluginContext::new(&mut parts, &mut ctx, None, Some(&mut resp));
            let rp = pctx.response_mut().expect("response should exist");
            rp.headers
                .insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("text/plain"));
        }
        assert_eq!(resp.headers.len(), 1);
    }

    /// PluginResponse::from_error 生成合法 JSON 且含错误码
    #[test]
    fn plugin_response_from_error_is_json() {
        let resp = PluginResponse::from_error(
            StatusCode::TOO_MANY_REQUESTS,
            "GATEWAY_RATE_LIMITED",
            "too many requests",
            Some("req-1"),
        );
        assert_eq!(resp.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers.get(http::header::CONTENT_TYPE),
            Some(&http::HeaderValue::from_static("application/json"))
        );
        let text = String::from_utf8_lossy(&resp.body);
        assert!(text.contains("GATEWAY_RATE_LIMITED"));
        assert!(text.contains("req-1"));
    }

    /// 插件超时返回 PluginError::Timeout
    #[tokio::test]
    async fn plugin_timeout_produces_timeout_error() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut slow = TestPlugin::new("slow", PluginPhase::Authentication, 10, log);
        // 睡眠 50ms，但 timeout() 声明为 sleep+10ms —— 这个测试里我们直接
        // 手工构造一个声明超时更短的链来验证超时路径
        slow.sleep = Some(Duration::from_millis(50));

        let chain = PluginChain::new(vec![Arc::new(slow)]);
        let mut parts = make_parts();
        let mut ctx = RequestContext::new(RequestId::new());
        let mut pctx = PluginContext::new(&mut parts, &mut ctx, None, None);

        // 正常情况下（timeout = sleep + 10ms）不应超时
        let ok = chain.run(&mut pctx).await;
        assert!(ok.is_ok(), "timeout should be larger than sleep");

        // 用一个声明超时 1ms 的插件验证超时触发
        struct TinyTimeoutPlugin;
        #[async_trait::async_trait]
        impl Plugin for TinyTimeoutPlugin {
            fn name(&self) -> &'static str {
                "tiny"
            }
            fn phase(&self) -> PluginPhase {
                PluginPhase::Authentication
            }
            fn timeout(&self) -> Option<Duration> {
                Some(Duration::from_millis(1))
            }
            async fn execute(
                &self,
                _ctx: &mut PluginContext<'_>,
            ) -> Result<PluginDecision, PluginError> {
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok(PluginDecision::Continue)
            }
        }

        let chain = PluginChain::new(vec![Arc::new(TinyTimeoutPlugin)]);
        let err = chain.run(&mut pctx).await.expect_err("should time out");
        assert!(matches!(err, PluginError::Timeout { .. }));
    }

    /// 计数器插件可用于验证 init 只调用一次
    struct CountingPlugin {
        inits: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Plugin for CountingPlugin {
        fn name(&self) -> &'static str {
            "counting"
        }
        fn phase(&self) -> PluginPhase {
            PluginPhase::RequestPreRoute
        }
        async fn init(&self) -> Result<(), PluginError> {
            self.inits.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn execute(
            &self,
            _ctx: &mut PluginContext<'_>,
        ) -> Result<PluginDecision, PluginError> {
            Ok(PluginDecision::Continue)
        }
    }

    /// init_all 对每个插件各调用一次 init
    #[tokio::test]
    async fn init_all_calls_each_plugin_once() {
        let counting = Arc::new(CountingPlugin {
            inits: AtomicUsize::new(0),
        });
        let mut registry = PluginRegistry::new();
        registry
            .register(counting.clone())
            .expect("register counting");
        registry.init_all().await.expect("init should succeed");
        assert_eq!(counting.inits.load(Ordering::SeqCst), 1);
    }
}
