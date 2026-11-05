先给出架构结论与 Phase 1 计划，确认后再动手写代码。

## 1. 现状检查

- 仓库根目录 `/Users/csy/my/github/standard-web` 只有 `README.md`、`docs/gateway设计文档.md` 和空的 `gateway/`。
- `gateway/` 内无任何 Cargo 文件，尚无 Workspace，可从零搭建，不存在覆盖已有代码的问题。
- 本机 Rust：`rustc 1.99.1`、`cargo 1.99.1`。
- 已查 crates.io 当前稳定版本：tokio 1.54.1、hyper 1.12.0、hyper-util 0.1.21、axum 0.8.9、tower 0.5.3、http 1.5.0、http-body-util 0.1.5、arc-swap 1.9.3、serde 1.0.229、serde_yaml_ng 0.10.0（`serde_yaml` 已标记 deprecated，改用 `serde_yaml_ng`）、thiserror 2.0.21、tracing 0.1.44、tracing-subscriber 0.3.23、clap 4.6.7、uuid 1.29.0、async-trait 0.1.92。

## 2. 最终 Workspace 结构（分阶段创建，避免空 Crate）

Phase 1 实际创建 9 个 crate；后续阶段按需增加，避免“提前建一堆空壳”。

```text
gateway/
├── Cargo.toml                     # workspace，统一版本/依赖/lints
├── rust-toolchain.toml            # stable
├── rustfmt.toml
├── clippy.toml
├── .gitignore
├── config/
│   ├── development.yaml
│   └── standalone.yaml
├── apps/
│   └── gateway/
│       ├── Cargo.toml
│       ├── src/main.rs
│       ├── src/cli.rs
│       ├── src/bootstrap.rs
│       └── tests/proxy_integration.rs
├── crates/
│   ├── gateway-common/            # 错误码、错误类型、RequestId、公共常量
│   ├── gateway-core/              # 领域模型 + 运行时 Trait + RequestContext（不依赖 IO/DB/HTTP 框架）
│   ├── gateway-config/            # YAML 加载、环境变量覆盖、Schema/引用校验
│   ├── gateway-routing/           # 路由表编译、确定性匹配、冲突检测
│   ├── gateway-discovery/         # ServiceDiscoveryProvider 实现（Phase 1: Static）
│   ├── gateway-upstream/          # 上游注册表、健康状态、负载均衡（Phase 1: Round Robin）
│   ├── gateway-proxy/             # Hyper 客户端、流式反向代理、Hop-by-Hop Header 处理
│   ├── gateway-network/           # Hyper Server、连接/并发限制、优雅关闭
│   ├── gateway-runtime/           # 数据面组合根：快照、Pipeline、Listener、Health(Admin)
│   └── gateway-observability/     # JSON 日志初始化、访问日志
└── deploy/
    └── docker/Dockerfile
```

后续阶段再新增（Phase 1 不建空壳）：

| 阶段 | 新增 Crate |
|---|---|
| Phase 2 | `gateway-security`、`gateway-traffic`、`gateway-resilience`、`gateway-plugin`、`gateway-transform` |
| Phase 3 | `gateway-control-api`、`gateway-control-service`、`gateway-storage`、`apps/gateway-control`、`apps/gatewayctl` |
| Phase 4 | `gateway-protocol` |
| Phase 5 | 扩展 `gateway-observability`（Prometheus/OTel） |

## 3. Crate 职责、公开接口与依赖方向

| Crate | 职责 | 主要公开接口 | 依赖 |
|---|---|---|---|
| `gateway-common` | 错误码与错误响应模型、RequestId、通用常量 | `GatewayError`、`ErrorCode`、`ErrorResponse`、`RequestId` | 无内部依赖 |
| `gateway-core` | 领域模型（Route/Service/Upstream/Endpoint/策略）、运行时 Trait、RequestContext | `RouteConfig`、`Endpoint`、`ServiceDiscoveryProvider`、`LoadBalancer`、`RouteResolver`、`RequestContext` | common, http, serde, async-trait |
| `gateway-config` | 配置文件结构、YAML 解析、环境变量覆盖、Schema/引用校验 | `GatewayConfig`、`load_from_path()`、`validate()` | common, core |
| `gateway-routing` | 不可变路由表、Host/Path/Method/Header/Query 匹配、优先级、冲突检测 | `RouteTable::compile()`、`RouteTable::resolve()` | common, core |
| `gateway-discovery` | 服务发现实现；Phase 1 静态 Provider | `StaticDiscoveryProvider` | common, core |
| `gateway-upstream` | 上游端点集合、健康状态、负载均衡策略 | `UpstreamRegistry`、`RoundRobinBalancer` | common, core |
| `gateway-proxy` | Hyper Client、URI 构造、请求头清洗、上游转发、错误映射 | `ProxyClient::forward()` | common, core, hyper, hyper-util |
| `gateway-network` | Hyper Server 接入、h1/h2、连接/并发限制、优雅关闭 | `HttpServer::serve()` | common |
| `gateway-observability` | Tracing JSON 初始化、访问日志 | `init_logging()`、`AccessLog::emit()` | common, tracing |
| `gateway-runtime` | 组合根：加载配置→编译快照→组装 Pipeline→启动 Listener/Health | `Runtime::start()`、`RuntimeHandle` | 全部数据面 crate + axum |
| `apps/gateway` | 仅 CLI 与 bootstrap，不承载业务逻辑 | `main()` → `bootstrap::run()` | gateway-runtime, clap |

依赖方向（无环）：

```text
apps/gateway
   └──> gateway-runtime
          ├──> gateway-config ──> gateway-core ──> gateway-common
          ├──> gateway-routing ─> gateway-core
          ├──> gateway-discovery ─> gateway-core
          ├──> gateway-upstream ─> gateway-core
          ├──> gateway-proxy ─> gateway-core
          ├──> gateway-network ─> gateway-common
          └──> gateway-observability ─> gateway-common
```

关键约束落实：

- `gateway-core` 不依赖 Axum、Hyper、SQLx、配置加载实现。
- Axum 只用于 Runtime 内的 `/health`、`/ready`、`/version`，不参与业务代理。
- 数据面请求走 Hyper Server → Tower Service（并发限制）→ Route → Endpoint → Hyper Client。
- 配置在启动时编译为不可变 `ArcSwap` 快照；请求热路径不读文件/DB。
- 无 `unwrap/expect` 处理生产逻辑；错误统一 `GatewayError`。

## 4. Phase 1 实施计划

1. Workspace 与基础工程文件（Cargo、fmt、clippy、toolchain、gitignore）。
2. `gateway-common`：错误码、统一错误 JSON、RequestId。
3. `gateway-core`：配置领域模型、Endpoint/Health、Trait、RequestContext。
4. `gateway-config`：YAML 加载、未知字段拒绝、环境变量覆盖、引用/默认值校验、明确错误路径。
5. `gateway-routing`：路由表编译、确定性匹配顺序、冲突检测、单元测试。
6. `gateway-upstream`：Static 注册表、Round Robin、空/不健康端点处理、单元测试。
7. `gateway-discovery`：Static Provider 实现。
8. `gateway-proxy`：Hyper 流式转发、URI/Header 处理、错误映射、单元测试。
9. `gateway-network`：Hyper h1/h2 接入、连接/并发限制、优雅关闭。
10. `gateway-observability`：JSON tracing 与访问日志。
11. `gateway-runtime`：配置→快照→Pipeline，启动业务 Listener 与 Axum Health 服务，优雅关闭。
12. `apps/gateway`：CLI（`--config`、`--check`）、bootstrap、SIGTERM/SIGINT。
13. 集成测试：真实 HTTP 请求 → 网关 → Mock 上游；覆盖 Host/Path/Method 路由、404、双实例轮询、上游连接失败 502、优雅关闭。
14. 配置示例、Dockerfile、README。
15. 编写 `docs/ARCHITECTURE.md`、`docs/DEVELOPMENT.md`。
16. 运行 `cargo fmt --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace`、`cargo build --workspace --release`，并如实报告结果。

Phase 1 明确不做：JWT/API Key/IP 控制、限流、重试、熔断、TLS、插件、动态配置热更新、控制面、gRPC、PostgreSQL、Metrics/OTel、WebSocket/SSE/gRPC 代理。

## 5. 需要确认的架构取舍

- 不全量创建 19 个 Crate，而是“最终结构在文档中定稿，代码按阶段落地”，符合“不允许过度拆分 Crate”。
- Phase 1 只支持 Standalone 模式（YAML）；Integrated/Distributed 在控制面阶段实现。
- 健康检查在 Phase 1 落地为 `/health`、`/ready`、`/version` 与上游连接失败处理；主动/被动端点健康检测留到后续阶段。

<AskUserQuestion>
<questions>
[{"question": "以上目录结构、模块职责、依赖方向与 Phase 1 范围是否符合需求？确认后我将创建骨架并实施 Phase 1。", "header": "架构确认", "options": [{"label": "确认架构，开始 Phase 1（推荐）", "description": "按上述 9 个 Phase 1 Crate、依赖方向和范围实施，完成后执行 fmt/clippy/test/build 并如实报告。"}, {"label": "先调整 Crate 划分", "description": "先讨论/修改 Crate 边界或依赖方向，暂不编码。"}, {"label": "先只写文档和骨架", "description": "只生成 ARCHITECTURE.md、DEVELOPMENT.md 和空的 Workspace 骨架，不实现代理逻辑。"}], "multiSelect": false}]
</questions>
</AskUserQuestion>