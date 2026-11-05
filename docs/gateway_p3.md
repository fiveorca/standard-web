## 一、Phase 3 范围界定
本阶段实现 （对应设计文档 4.11 与 8.x）：

Axum Admin API · PostgreSQL/SQLx · 配置校验 · 配置编译 · 配置版本 · 配置快照 · 动态更新 · 配置回滚 · 审计日志

明确不在本阶段 ：

能力 归属 gRPC 注册 / 心跳 / Snapshot 分发 / ACK-NACK Phase 4 多实例配置同步、控制面失联重连 Phase 4 Prometheus / OTel / 完整 E2E Phase 5 Canary / 镜像 / K8s 发现 / Redis 限流 Phase 6

## 二、目录结构
### 新增
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37

`gateway/
├── crates/
│   ├── gateway-storage/              # 唯一允许触达 PostgreSQL 的 crate（控制面专用）
│   │   └── src/
│   │       ├── lib.rs                # 公开接口导出
│   │       ├── error.rs              # StorageError
│   │       ├── pool.rs               # PgPool 构建 + 连接参数 + acquire_timeout
│   │       ├── models.rs             # 持久化记录（Record）与领域模型的双向转换
│   │       ├── repository.rs         # GatewayRepository trait（全部聚合的读写契约）
│   │       ├── memory.rs             # 内存实现（测试与集成模式默认）
│   │       └── postgres.rs           # SQLx 实现（运行时查询，不用 query! 宏）
│   │
│   ├── gateway-control-service/      # 配置生命周期 + 审计（纯业务，不含 HTTP/DB 细节）
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── error.rs              # ControlError（可映射为统一错误码）
│   │       ├── config_service.rs     # 资源 CRUD + 校验 + 编译编排
│   │       ├── publish.rs            # 发布 / 回滚原子流程
│   │       └── audit.rs              # 审计写入
│   │
│   └── gateway-control-api/          # Axum 路由层：DTO / 鉴权 / 分页 / 错误映射
│       └── src/
│           ├── lib.rs
│           ├── router.rs             # /api/admin/v1 路由树
│           ├── state.rs             # AppState（Service + SnapshotStore）
│           ├── auth.rs              # Bearer Token + RBAC middleware
│           ├── error.rs             # 统一 JSON 错误结构
│           ├── dto.rs               # 请求 / 响应 DTO + 分页参数
│           └── handlers/            # 按资源拆分 handler
│
├── apps/
│   └── gateway-control/              # 独立控制面二进制（Distributed 模式用）
│       └── src/{main.rs, bootstrap.rs, cli.rs}
│
└── migrations/
    └── 20260101000000_init.sql       # 设计文档第十章要求的全部表
`

### 修改
文件/目录 变更内容 Cargo.toml members 增加 3 个 crate + 1 个 app；workspace deps 增加`sqlx` /`chrono` /`sha2` `crates/gateway-config/` 新增`compile.rs` （引用解析 + 编译为快照）、`snapshot.rs` （版本/校验和/不可变快照结构） `crates/gateway-runtime/` 新增`state.rs` （`SnapshotStore` ：`ArcSwap<CompiledSnapshot>` + 原子`apply` ）；请求路径从 store 读取，不查 DB `apps/gateway/` bootstrap 支持 integrated 模式：可挂载 Admin Router 并注入同一个`SnapshotStore`

### 刻意不新增
- 不建`gateway-compiler` 独立 crate ：编译逻辑放`gateway-config` ，避免为目录数量强行拆包（违反 18.2.11）
- 不建`gateway-protocol` ：Phase 4 才需要 gRPC proto
## 三、模块职责
### gateway-storage
项 职责 `GatewayRepository` trait 15 类聚合的读写：routes / services / upstreams / endpoints / consumers / credentials / auth / rate-limit / retry / circuit-breaker policies / plugins / config_versions / publish_records / audit_logs `memory.rs` 全部 trait 方法的内存实现；供单元/集成测试与 integrated 模式使用， 不需要 PG `postgres.rs` SQLx 实现。 只用`sqlx::query` 运行时绑定，不用`query!` 编译期宏 ，保证无`DATABASE_URL` 也能`cargo build` `pool.rs` `PgPoolOptions` ：max_connections / acquire_timeout / 启动时执行`sqlx::migrate!` 表设计 业务字段用 JSONB 载荷 + 关键列（id/name/enabled/config_version/created_at/updated_at/checksum）建索引；满足第十章全部表清单，同时避免 15 张表各写几十列

### gateway-control-service
组件 职责 `config_service` 资源 CRUD；写入前做 schema 校验（复用 gateway-config 的 validator）+ 引用完整性校验（route→service→upstream→endpoint） `publish` 原子发布 ：读全量资源 → 引用校验 → 编译 → 生成 checksum/version → 事务内写`config_versions` (PUBLISHED) +`config_publish_records` + 审计 → 提交后`SnapshotStore.apply()` 。任一步失败：不写库、不动快照、返回 NACK 语义错误 `rollback` 读取目标历史版本的快照内容， 作为新版本重新发布 （版本号单调递增，绝不倒退，符合 9.4） `audit` 记录 operator / operation / resource_type / resource_id / before / after / result / ip / created_at

### gateway-control-api
项 职责 路由 系统（health/ready/version/instances）；routes；services；upstreams(+endpoints)；consumers(+credentials)；四类 policy；plugins；config（validate/compile/publish/versions/rollback）；audit-logs `auth.rs` Bearer Token（静态 token 清单）+ 两级角色`admin` /`viewer` ；写操作必须 admin `error.rs` 统一结构`{code, message, request_id, trace_id}` ；不泄露堆栈与密钥 默认监听 `127.0.0.1` ，绝不与业务 Listener 共用端口（满足 8 与 13.1）

### gateway-runtime 的改动（数据面唯一变化）
text

1
2
3
4

`请求 → 读 SnapshotStore（ArcSwap 原子读，无锁无 DB）
     → 路由匹配 / 限流 / 熔断 / 代理
配置发布 → SnapshotStore.apply(新快照)   # 单次原子指针交换
`

发布失败时指针不交换，在途请求继续使用旧快照——满足「更新失败不破坏现有配置」。

## 四、依赖关系
text

1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19

`apps/gateway            apps/gateway-control
        │                        │
        │                        v
        │              gateway-control-api
        │                        │
        │                        v
        │              gateway-control-service
        │                   │         │
        │                   v         v
        │            gateway-storage  gateway-config
        │                   │         │
        └──────────┬────────┘         │
                   v                  v
             gateway-core  ←──── gateway-config
                   ↑
             gateway-routing
                   ↑
             gateway-runtime ──→ gateway-config（读 CompiledSnapshot）
`

硬性约束：

1. `gateway-runtime` 不依赖`gateway-storage` /`gateway-control-*` → 数据面无法触达 PG
2. `gateway-control-api` 不被 runtime 依赖 → 管理接口不会混入业务链路
3. `gateway-storage` 只依赖`gateway-common` +`gateway-core`
4. `gateway-config` 不依赖`gateway-routing` → 保持纯数据编译，`RouteTable` 由 runtime 在 apply 时构建
5. 无环、无循环依赖
## 五、实施计划
子阶段 内容 验收 3.1 workspace 注册 +`gateway-storage` 骨架：error / models / repository trait / memory 实现 / migrations SQL 内存仓储单元测试全过 3.2 `pool.rs` +`postgres.rs` （SQLx 运行时查询）+ 迁移执行 无 PG 也能编译；PG 集成测试`#[ignore]` +`GATEWAY_TEST_DATABASE_URL` 门控 3.3 `gateway-config` ：`compile.rs` （引用校验 + 编译）+`snapshot.rs` （checksum/version） 编译失败场景（悬空 service_id、重复 id）均有测试 3.4 `gateway-control-service` ：CRUD / publish / rollback / audit 发布失败保持旧快照；回滚生成新版本号 3.5 `gateway-control-api` ：路由树 / DTO / auth / 统一错误 / 分页 `tower::ServiceExt::oneshot` 直测 Router，无需起端口 3.6 `apps/gateway-control` 独立二进制 +`apps/gateway` integrated 模式（共享`SnapshotStore` ，热更新） 发布新配置后数据面立即用新快照，进程不重启 3.7 收尾：文档更新 + 阶段报告 四条命令全绿

每一步完成后运行：`cargo check --workspace` /`cargo clippy --workspace --all-targets -- -D warnings` /`cargo test --workspace` /`cargo build --workspace --release` 。

### 测试策略（关键决策点）
层级 方式 是否需要 PG 单元测试 各 crate 内部`#[cfg(test)]` 否 集成测试 `memory.rs` 仓储 + Axum`oneshot` 否 PG 集成测试 `#[ignore]` ，读`GATEWAY_TEST_DATABASE_URL` 是（可选执行）

这样在无 PostgreSQL 的机器上 CI 依然全绿，同时保留了真实 PG 的验证路径。

以下三个决策点需要你确认，确认后我立即从 3.1 开始实现。

已对用户提问

架构已确认。上下文已接近上限，且剩余 7 个子阶段的实现量较大，我先切换到一个干净的上下文继续实现，避免中途被压缩丢失已确认的设计。

已读取 19 个文件，搜索 5 次文件，执行 4 条命令

Phase 3 架构已确认，开始按里程碑实现。先对齐结构：

层 Crate 职责 依赖 存储 `gateway-storage` 资源仓储 trait、memory/PG 实现、迁移 SQL common/core + sqlx/chrono 编译 `gateway-config` （扩展） 资源校验复用、`CompiledSnapshot` 、checksum/版本 现有依赖 + sha2 控制服务 `gateway-control-service` CRUD、发布、回滚、审计、快照应用回调 storage/config 控制 API `gateway-control-api` Axum 路由、DTO、Bearer+RBAC、统一错误 control-service 入口 `apps/gateway-control` 独立控制面二进制 control-api/storage 热更新 `gateway-runtime` （扩展） `SnapshotStore` (ArcSwap)、原子 apply 现有依赖 集成 `apps/gateway` integrated 模式挂载 Admin API +control-api/storage

依赖方向无环：`storage ← service ← api ← apps` ；`runtime` 不依赖`storage/control-*` 。