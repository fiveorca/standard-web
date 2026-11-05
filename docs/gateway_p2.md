我按照设计文档 [gateway设计文档.md](file:///Users/csy/my/github/standard-web/docs/gateway设计文档.md) 第十七章定义的 Phase 2（基础网关治理）梳理方案。上一轮提到的“响应流式透传”作为 **P2.0 基础设施**先行落地，因为鉴权、超时、重试、埋点都依赖正确的流式 Body 抽象。

## 一、Phase 2 范围

| 来源 | 内容 |
|---|---|
| 设计文档 Phase 2 | JWT、API Key、IP 黑白名单、Token Bucket、Fixed Window、Request ID、CORS、Timeout、Retry、Circuit Breaker、基础插件系统、请求转换、响应头转换 |
| 上轮追加 | 响应流式透传（成功路径不再 `collect()`） |
| 明确不做（P1/后续阶段） | Redis 分布式限流、Sliding/Leaky Window、OAuth2/OIDC/mTLS、Body 内容转换、灰度/镜像流量、TLS、WAF、动态 `.so` 插件 |

## 二、目录结构

```text
gateway/
├── crates/
│   ├── gateway-common/
│   │   └── src/error.rs                 [改] 新增 Auth/RateLimit/Circuit/Retry 相关错误构造
│   ├── gateway-core/
│   │   ├── src/policy.rs                [新] 策略配置模型（Auth/RateLimit/Timeout/Retry/CB/Cors/Plugin）
│   │   ├── src/request_context.rs       [改] consumer、auth_result、retry_count、circuit_state、peer_ip
│   │   └── src/lib.rs                   [改] 导出 policy
│   ├── gateway-config/
│   │   ├── src/config.rs                [改] GatewayConfig 增加策略段
│   │   └── src/validator.rs             [改] 策略 ID 唯一性、route 引用完整性、参数边界校验
│   ├── gateway-security/                [新]
│   │   ├── src/lib.rs
│   │   ├── src/jwt.rs                   JWT 解析/验签/算法白名单/过期与 iss/aud
│   │   ├── src/api_key.rs               API Key 摘要校验（constant-time）
│   │   ├── src/basic.rs                 Basic Auth
│   │   ├── src/ip_filter.rs             IP Allow/Deny（CIDR）
│   │   └── src/layer.rs                 Tower Layer + Service
│   ├── gateway-traffic/                 [新]
│   │   ├── src/lib.rs
│   │   ├── src/token_bucket.rs
│   │   ├── src/fixed_window.rs
│   │   ├── src/key.rs                   限流 key 提取（global/ip/route/consumer/api_key）
│   │   └── src/layer.rs                 Tower Layer，返回 429 + Retry-After
│   ├── gateway-resilience/              [新]
│   │   ├── src/lib.rs
│   │   ├── src/circuit_breaker.rs       CLOSED/OPEN/HALF_OPEN 状态机
│   │   ├── src/retry.rs                 退避 + 抖动 + 可重试判定
│   │   ├── src/timeout.rs
│   │   ├── src/bulkhead.rs              并发信号量
│   │   └── src/layer.rs
│   ├── gateway-transform/               [新]
│   │   ├── src/lib.rs
│   │   ├── src/header.rs                Request/Response Header Add/Remove/Replace
│   │   ├── src/path.rs                  Path/Host/Query 重写
│   │   ├── src/cors.rs                  Preflight + 响应头注入
│   │   └── src/layer.rs
│   ├── gateway-plugin/                  [新]
│   │   ├── src/lib.rs
│   │   ├── src/stage.rs                 执行阶段枚举 + 排序
│   │   ├── src/plugin.rs                GatewayPlugin trait
│   │   └── src/registry.rs              编译时注册表
│   ├── gateway-network/
│   │   └── src/server.rs                [改] 注入 PeerAddr extension；ResBody 约束放宽为 Send
│   ├── gateway-runtime/
│   │   ├── src/body.rs                  [新] ResBody 别名、流式包装、错误响应构造
│   │   ├── src/policy_store.rs          [新] 配置 → 运行时策略实例
│   │   ├── src/pipeline.rs              [改] Tower ServiceBuilder 组装
│   │   ├── src/admin.rs                 [改] 移除 local_addr().unwrap()
│   │   └── src/runtime.rs               [改] 流式透传 + Pipeline 接入
│   └── ...
├── config/
│   └── development.yaml                 [新] Phase 2 示例配置
└── tests/
    ├── integration/                     [新] wiremock 端到端
    └── mock-services/                   [新] 可选测试后端
```

## 三、模块职责

| 模块 | 职责 | 明确不负责 |
|---|---|---|
| gateway-core/policy | 纯数据模型 + 默认值，供 config 反序列化和运行时实例化 | 不引用 tokio/hyper |
| gateway-security | 身份识别与访问资格：JWT/API Key/Basic/IP | 不选上游、不改路由、不做业务权限 |
| gateway-traffic | 本地限流算法与 key 策略，返回 429/Retry-After | 不做分布式存储（P1 Redis） |
| gateway-resilience | 超时、重试、熔断、Bulkhead | 不构造上游 URI、不管理连接池 |
| gateway-transform | Header/Path/Host/Query 重写、CORS | 不缓冲 Body（Body 转换留后续） |
| gateway-plugin | 阶段定义、Trait、注册表、确定性排序、短路 | 不直接依赖具体治理 crate，避免循环 |
| gateway-runtime | 唯一组合根：加载配置、编译策略、组装 Pipeline、管理生命周期 | 不实现策略算法 |
| gateway-network | 纯 IO + PeerAddr 注入 | 不解析业务策略 |

## 四、依赖关系

```text
apps/gateway
      │
      ▼
gateway-runtime ─────────────────────────┐
   │  │  │  │  │  │  │  │  │  │           │
   │  │  │  │  │  │  │  │  │  └─► gateway-config
   │  │  │  │  │  │  │  │  └────► gateway-observability
   │  │  │  │  │  │  │  └───────► gateway-upstream
   │  │  │  │  │  │  └──────────► gateway-routing
   │  │  │  │  │  └─────────────► gateway-network
   │  │  │  │  └────────────────► gateway-proxy
   │  │  │  └───────────────────► gateway-plugin
   │  │  └──────────────────────► gateway-transform
   │  └─────────────────────────► gateway-resilience
   └────────────────────────────► gateway-security / gateway-traffic

security / traffic / resilience / transform / plugin
      │
      ▼
gateway-core ──► gateway-common
```

约束：
- 五个治理 crate **互不依赖**，只依赖 `gateway-common` + `gateway-core`。
- `gateway-plugin` 只定义抽象，不依赖 `gateway-security` 等实现 crate，避免反向依赖。
- `gateway-runtime` 是唯一可以把它们组合起来的 crate。
- 不新增过小 crate：`body.rs`、`policy_store.rs` 放在 runtime/core 内，不单独拆 crate。

## 五、关键设计决策

1. **流式 Body（P2.0）**
   - `type ResBody = BoxBody<Bytes, BoxError>`，成功路径 `upstream_resp.map(|b| b.boxed())`，不再 `collect()`。
   - 错误路径 `Full::new(json_bytes).boxed()`，一并移除 `Response::builder().unwrap()`。
   - 先验证 `hyper::body::Incoming: Sync`；若编译不通过，改用 `UnsyncBoxBody` 并把 `gateway-network::serve` 的 `ResBody: Sync` 放宽为 `Send`（hyper 的 `serve_connection` 本身不要求 Sync）。
   - AccessLog 改为 `ObservedBody` 包装：body 读完/断开时才 `emit`，否则流式响应会把耗时统计成“首包时间”。

2. **超时分层**
   - Connect Timeout 由 `HttpConnector` 控制；Response Header / 总请求超时用 `tokio::time::timeout` 包住 `forward()`。
   - Body 读取超时在 P2 只做“首包 + 总时长”，逐帧读超时留后续阶段，避免过度设计。

3. **重试安全**
   - 只有幂等方法且 `Content-Length: 0`/无 `Transfer-Encoding` 才允许重试；有 Body 的请求一律不重试。
   - 为支持重试，`ProxyClient` 的 `ReqBody` 改为 `BoxBody<Bytes, BoxError>`：首次用原始 `Incoming`，重试用 `Empty<Bytes>`。
   - 重试必须换端点：`UpstreamRegistry` 提供“排除已失败端点”的选择接口。

4. **CORS 与执行顺序**
   - `OPTIONS + Access-Control-Request-Method` 在鉴权/限流之前短路返回 204。
   - 其余按设计文档第五章：IP 过滤 → 路由 → 认证 → 授权 → CORS → 限流 → 转换 → 上游。

5. **客户端 IP**
   - `gateway-network` 把 `peer_addr` 作为 request extension 注入；runtime 读取后填 `RequestContext.client_ip`，供 IP 黑白名单和限流 key 使用。

6. **插件系统**
   - `GatewayPlugin` trait + `PluginStage` 枚举 + `priority` 排序；短路返回统一错误响应。
   - 内置插件以适配器形式注册，禁止动态 `.so`；Phase 2 只做编译时注册。

## 六、实施计划

| 步骤 | 内容 | 验收 |
|---|---|---|
| P2.0 | 流式 `ResBody`、`ObservedBody`、错误响应去 `unwrap`、PeerAddr 注入、`ProxyClient` Body 泛型改造 | 大响应不再全量缓冲；36 个既有测试 + clippy 通过 |
| P2.1 | `gateway-core/policy.rs` + `gateway-config` 新配置段与校验 | YAML 解析/校验单测；错误路径带字段名 |
| P2.2 | `gateway-plugin` 阶段/trait/registry | 阶段排序、短路单测 |
| P2.3 | `gateway-security`：IP → Basic/API Key → JWT | 401/403 单测；认证失败请求不触达上游 |
| P2.4 | `gateway-traffic`：Token Bucket / Fixed Window / key 策略 | 429 + `Retry-After`；并发与窗口边界测试 |
| P2.5 | `gateway-transform`：Header/Path 重写 + CORS | Preflight 204；请求/响应头增删改测试 |
| P2.6 | `gateway-resilience`：Timeout / Retry / Circuit Breaker / Bulkhead | 熔断三态恢复测试；非幂等不重试；超时映射 504 |
| P2.7 | runtime Pipeline 组装 + wiremock 集成测试 + 示例 YAML | 策略组合执行正确；`cargo check/clippy -D warnings/test/build --release` 全绿 |

## 七、需要你确认的两点

<AskUserQuestion>
<questions>
<question>Phase 2 的实施范围按哪个口径执行？</question>
<header>实施范围</header>
<multiSelect>false</multiSelect>
<options>
<label>完整 Phase 2（推荐）</label>
<description>P2.0~P2.7 全部执行：流式透传 + 安全 + 限流 + 转换 + 韧性 + 插件 + 集成测试</description>
<label>先做 P2.0~P2.4</label>
<description>先落地流式透传、策略模型、插件骨架、安全、限流，转换与韧性下一批</description>
<label>只做 P2.0 + P2.1</label>
<description>只做流式透传与配置/策略模型，快速验证架构方向</description>
</options>
</questions>
<questions>
<question>JWT 在 Phase 2 的密钥来源采用哪种实现？</question>
<header>JWT 实现</header>
<multiSelect>false</multiSelect>
<options>
<label>静态密钥 + 算法白名单（推荐）</label>
<description>配置中提供 secret/public key，严格算法白名单、过期/iss/aud 校验；无外部依赖，便于测试</description>
<label>静态密钥 + JWKS 远程缓存</label>
<description>额外实现 JWKS 拉取、缓存与 key rotation，复用 hyper-util client，复杂度更高</description>
</options>
</questions>
</AskUserQuestion>

确认后我将从 P2.0 开始按里程碑实现，每步都补充逐行中文注释（含所调用 crate API 的参数说明），并在每个里程碑后运行 `cargo check / clippy -D warnings / test`。