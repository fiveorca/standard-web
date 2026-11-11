# HTTP API

- Base URL：`http://<host>:8080`
- 版本前缀：`/api/v1`
- 数据格式：`application/json; charset=UTF-8`
- 时间格式：ISO 8601（UTC），例如 `2026-01-01T12:00:00Z`
- OpenAPI：`/v3/api-docs`，Swagger UI：`/docs`

## 1. 统一响应

成功：

```json
{
  "code": 0,
  "message": "success",
  "data": {},
  "timestamp": "2026-01-01T12:00:00Z"
}
```

分页 `data`：

```json
{
  "items": [],
  "total": 0,
  "page": 1,
  "size": 20
}
```

失败：

```json
{
  "code": 42201,
  "error": "validation_failed",
  "message": "参数校验失败",
  "details": { "deviceId": "长度不能超过 128" },
  "timestamp": "2026-01-01T12:00:00Z"
}
```

分页参数：`page` 从 1 开始，默认 1；`size` 默认 20，最大 200。

## 2. 认证

| 接口范围 | 认证方式 |
| --- | --- |
| `/api/v1/admin/**` | `X-API-Key: <IM_ADMIN_API_KEY>` 或 `Authorization: Bearer <JWT>`（需管理员角色） |
| `/api/v1/device/**` | `X-Device-Id` + `X-Device-Token`，或 `Authorization: Bearer <JWT>`（含 `device_id`） |
| `/api/v1/internal/**` | `X-Internal-Token: <IM_INTERNAL_TOKEN>` |
| `/actuator/health`、`/actuator/info`、`/docs`、`/v3/api-docs` | 公开 |

JWT 使用 `IM_JWT_ROLES_CLAIM`（默认 `roles`）判断管理角色，使用 `IM_JWT_TENANT_CLAIM`（默认 `tenant_id`）判断租户。请求中的 `tenantId` 与 JWT 租户不一致时返回 403。

## 3. 错误码

| HTTP | code | error | 说明 |
| --- | --- | --- | --- |
| 400 | 40001 | `invalid_request` | 请求参数不合法 |
| 401 | 40101 | `unauthorized` | 未认证或凭证无效 |
| 403 | 40301 | `forbidden` | 无权限 / 租户不匹配 |
| 404 | 40401 | `not_found` | 资源不存在 |
| 409 | 40901 | `conflict` | 唯一约束冲突 / 状态冲突 |
| 413 | 41301 | `payload_too_large` | 请求体或附件过大 |
| 415 | 41501 | `unsupported_media_type` | Content-Type 不支持 |
| 422 | 42201 | `validation_failed` | 字段校验失败 |
| 429 | 42901 | `rate_limited` | 触发限流 |
| 502 | 50201 | `provider_error` | 外部供应商错误 |
| 503 | 50301 | `unavailable` | Broker / 配置不可用 |
| 500 | 50001 | `internal_error` / `database_error` | 服务器内部错误 |

## 4. MQTT Broker 管理

`/api/v1/admin/mqtt/brokers`

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 分页查询，参数 `page`、`size`、`q` |
| POST | `/` | 新增 |
| GET | `/{id}` | 详情 |
| PUT | `/{id}` | 修改 |
| DELETE | `/{id}` | 删除（存在接入配置时拒绝） |
| POST | `/{id}/enable` | 启用 |
| POST | `/{id}/disable` | 禁用 |
| POST | `/{id}/default` | 设为默认 Broker |
| POST | `/{id}/test` | 测试连接 |
| GET | `/{id}/status` | 运行状态 |

新增/修改请求：

```json
{
  "code": "emqx-prod",
  "name": "EMQX Production",
  "brokerType": "EMQX",
  "host": "emqx.example.com",
  "tcpPort": 1883,
  "tlsPort": 8883,
  "protocolVersion": "5.0",
  "tlsEnabled": true,
  "username": "im-service",
  "password": "broker-password",
  "clientIdPrefix": "im-service-publisher",
  "keepAliveSeconds": 60,
  "cleanStart": true,
  "sessionExpirySeconds": 0,
  "connectTimeoutSeconds": 10,
  "reconnectDelaySeconds": 5,
  "maxInflight": 100,
  "enabled": true,
  "defaultBroker": false,
  "optionsJson": "{}"
}
```

响应不返回 `password`，只返回 `hasPassword`。

## 5. MQTT 接入配置

`/api/v1/admin/mqtt/access-configs`

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 分页查询，参数 `page`、`size`、`q`、`tenantId` |
| POST | `/` | 新增 |
| GET | `/{id}` | 详情 |
| PUT | `/{id}` | 修改（`configVersion + 1`） |
| DELETE | `/{id}` | 逻辑删除（存在设备凭证时拒绝） |
| POST | `/{id}/enable` / `/{id}/disable` | 启停 |
| POST | `/{id}/default` | 设为默认接入配置 |
| GET | `/{id}/acls` | 查询 Topic ACL |
| POST | `/{id}/acls` | 新增 Topic ACL |
| DELETE | `/{id}/acls/{aclId}` | 删除 Topic ACL |

请求示例：

```json
{
  "code": "default",
  "name": "Default Access Config",
  "tenantId": null,
  "brokerId": "0b0d6d8e-6e26-4f4e-9d1a-2f3e2c0e4a11",
  "enabled": true,
  "defaultConfig": true,
  "protocolVersion": "5.0",
  "defaultQos": 1,
  "keepAliveSeconds": 60,
  "cleanStart": true,
  "sessionExpirySeconds": 0,
  "messageExpiryIntervalSeconds": 3600,
  "retainDefault": false,
  "publishTopicTemplate": "devices/{deviceId}/up",
  "subscribeTopicTemplate": "devices/{deviceId}/down",
  "serviceTopicPrefix": "tenants/",
  "tlsEnabled": false,
  "authMode": "CREDENTIAL",
  "metadataJson": "{}"
}
```

ACL 请求：

```json
{
  "subjectType": "DEVICE",
  "subjectId": "device-001",
  "topicPattern": "devices/device-001/#",
  "action": "SUBSCRIBE",
  "effect": "ALLOW",
  "qosMax": 2,
  "priority": 10,
  "enabled": true
}
```

## 6. 设备 MQTT 凭证管理

`/api/v1/admin/mqtt/credentials`

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 分页查询，参数 `page`、`size`、`tenantId`、`deviceId` |
| POST | `/` | 创建设备凭证 |
| GET | `/{id}` | 详情（不含密码） |
| POST | `/{id}/rotate` | 轮换密码，返回新密码一次 |
| POST | `/{id}/disable?reason=` | 禁用 |
| POST | `/{id}/revoke?reason=` | 撤销（不可恢复） |
| GET | `/version?deviceId=&tenantId=` | 查询设备当前配置版本 |

创建请求：

```json
{
  "tenantId": null,
  "deviceId": "device-001",
  "accessConfigId": null,
  "expiresAt": "2027-01-01T00:00:00Z",
  "createDefaultAcls": true
}
```

`accessConfigId` 为空时使用该租户的默认接入配置。响应：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "credential": {
      "id": "1d6f5f6a-5e4f-4a6e-9f3a-2b1c0d9e8f70",
      "tenantId": null,
      "deviceId": "device-001",
      "accessConfigId": "…",
      "brokerId": "…",
      "username": "dev_7f3c9a2b8e4d",
      "status": "ACTIVE",
      "configVersion": 1,
      "expiresAt": "2027-01-01T00:00:00Z",
      "createdAt": "2026-01-01T00:00:00Z",
      "updatedAt": "2026-01-01T00:00:00Z"
    },
    "password": "一次性明文密码"
  }
}
```

> `password` 只在创建和轮换时返回，请立即交付设备，服务端仅保存摘要与密文。

## 7. 设备获取 MQTT 配置

`/api/v1/device/mqtt`

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/config` | 当前设备的完整 MQTT 连接配置 |
| GET | `/config/version` | 当前配置版本 |

请求头：

```http
X-Device-Id: device-001
X-Device-Token: <创建凭证时返回的密码>
```

响应 `data`：

```json
{
  "tenantId": null,
  "deviceId": "device-001",
  "brokerUrl": "tcp://emqx.example.com:1883",
  "port": 1883,
  "protocolVersion": "5.0",
  "tlsEnabled": false,
  "clientId": "dev_7f3c9a2b8e4d",
  "username": "dev_7f3c9a2b8e4d",
  "password": "设备 MQTT 密码",
  "keepAlive": 60,
  "cleanStart": true,
  "sessionExpiry": 0,
  "defaultQos": 1,
  "publishTopic": "devices/device-001/up",
  "subscribeTopic": "devices/device-001/down",
  "topicPermissions": [
    { "topic": "devices/device-001/#", "action": "SUBSCRIBE", "effect": "ALLOW", "qosMax": 2 }
  ],
  "configVersion": 1,
  "accessConfigVersion": 1,
  "expiresAt": null
}
```

设备只能获取自己的配置；错误令牌返回 401。

## 8. MQTT 发送记录

`/api/v1/admin/mqtt/publish-records`

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 分页查询，参数 `page`、`size`、`tenantId`、`deviceId`、`status`（`PENDING`/`PUBLISHED`/`FAILED`） |
| GET | `/{id}?tenantId=` | 详情 |

记录包含 `messageId`、`deviceId`、`topic`、`contentType`、`payloadSize`、`qos`、`retained`、`status`、`errorCode`、`errorMessage`、`traceId`、`publishedAt`。

## 9. 邮件发送方管理

`/api/v1/admin/email/senders`

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 分页查询，参数 `page`、`size`、`q`、`tenantId` |
| POST | `/` | 新增 |
| GET | `/{id}` | 详情（不含 SMTP 密码） |
| PUT | `/{id}` | 修改 |
| DELETE | `/{id}` | 删除（存在任务引用时拒绝） |
| POST | `/{id}/enable` / `/{id}/disable` | 启停 |
| POST | `/{id}/default` | 设为默认发送方 |
| PUT | `/{id}/password` | 独立更新 SMTP 密码 |
| POST | `/{id}/test-connection` | 测试 SMTP 连接 |
| POST | `/{id}/test-email` | 发送测试邮件 |

新增请求：

```json
{
  "tenantId": null,
  "code": "noreply",
  "name": "No Reply",
  "fromAddress": "noreply@example.com",
  "fromName": "Example Platform",
  "providerType": "SMTP",
  "defaultSender": true,
  "enabled": true,
  "ratePerMinute": 60,
  "ratePerDay": 5000,
  "smtp": {
    "host": "smtp.example.com",
    "port": 587,
    "username": "noreply@example.com",
    "password": "smtp-password",
    "auth": true,
    "ssl": false,
    "starttls": true,
    "connectionTimeoutMs": 10000,
    "readTimeoutMs": 30000,
    "writeTimeoutMs": 30000
  }
}
```

修改密码：

```json
{ "password": "new-smtp-password" }
```

测试邮件：

```json
{ "to": "ops@example.com" }
```

测试连接返回：

```json
{ "success": true, "latencyMs": 123, "message": "SMTP 连接成功" }
```

## 10. 邮件任务与发送记录

`/api/v1/admin/email`

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/tasks` | 分页查询，参数 `page`、`size`、`tenantId`、`senderId`、`status` |
| GET | `/tasks/status?taskId=&requestId=&tenantId=` | 按任务 ID 或请求 ID 查询状态 |
| GET | `/tasks/{id}?tenantId=` | 详情（任务 + 收件人 + 附件 + 发送记录） |
| POST | `/tasks/{id}/retry` | 手动重试失败任务 |
| GET | `/tasks/{id}/records` | 任务发送记录，参数 `page`、`size` |
| GET | `/records` | 发送记录分页，参数 `page`、`size`、`tenantId`、`senderId` |

任务状态：`PENDING` / `PROCESSING` / `SUCCESS` / `RETRYING` / `FAILED`。

详情响应结构：

```json
{
  "task": {
    "id": "…",
    "tenantId": null,
    "requestId": "req-20260101-0001",
    "senderId": "…",
    "subject": "欢迎注册",
    "status": "SUCCESS",
    "attemptCount": 1,
    "maxAttempts": 5,
    "nextRetryAt": null,
    "lastErrorCode": null,
    "lastErrorMessage": null,
    "providerMessageId": "<task-id@im-service>",
    "acceptedAt": "2026-01-01T12:00:00Z",
    "startedAt": "2026-01-01T12:00:02Z",
    "finishedAt": "2026-01-01T12:00:03Z",
    "payloadSize": 2048,
    "createdAt": "2026-01-01T12:00:00Z",
    "updatedAt": "2026-01-01T12:00:03Z"
  },
  "recipients": [
    { "type": "TO", "address": "user@example.com", "displayName": null }
  ],
  "attachments": [
    { "id": "…", "filename": "welcome.pdf", "contentType": "application/pdf", "size": 10240 }
  ],
  "sendRecords": [
    {
      "id": "…",
      "attempt": 1,
      "status": "SUCCESS",
      "provider": "SMTP",
      "providerMessageId": "<task-id@im-service>",
      "errorCode": null,
      "errorMessage": null,
      "durationMs": 812,
      "createdAt": "2026-01-01T12:00:03Z"
    }
  ]
}
```

## 11. 内部回调（EMQX）

`/api/v1/internal/mqtt`

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/auth` | MQTT 用户名/密码认证 |
| POST | `/acl` | Topic 发布/订阅授权 |

请求：

```json
{ "username": "dev_xxx", "password": "…", "clientid": "device-001", "peerhost": "10.0.0.1" }
```

```json
{ "username": "dev_xxx", "topic": "devices/device-001/up", "action": "publish", "clientid": "device-001" }
```

响应：

```json
{ "result": "allow", "is_superuser": false }
```

或 `{"result":"deny","is_superuser":false}`。必须携带 `X-Internal-Token`。

## 12. Java HTTP 调用示例

使用 Java 11+ 标准 `HttpClient`（无需额外依赖）：

```java
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class ImHttpClientExample {
    private static final String BASE = "http://localhost:8080";

    public static void main(String[] args) throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        // 1. 创建 MQTT Broker
        String brokerJson = """
                {
                  "code": "emqx-local",
                  "name": "EMQX Local",
                  "host": "localhost",
                  "tcpPort": 1883,
                  "protocolVersion": "5.0",
                  "enabled": true,
                  "defaultBroker": true
                }
                """;
        HttpRequest createBroker = HttpRequest.newBuilder(URI.create(BASE + "/api/v1/admin/mqtt/brokers"))
                .header("Content-Type", "application/json")
                .header("X-API-Key", System.getenv("IM_ADMIN_API_KEY"))
                .POST(HttpRequest.BodyPublishers.ofString(brokerJson))
                .timeout(Duration.ofSeconds(10))
                .build();
        HttpResponse<String> brokerResponse = client.send(createBroker, HttpResponse.BodyHandlers.ofString());
        System.out.println("broker: " + brokerResponse.statusCode() + " " + brokerResponse.body());

        // 2. 创建设备凭证
        String credentialJson = """
                { "deviceId": "device-001", "createDefaultAcls": true }
                """;
        HttpRequest createCredential = HttpRequest.newBuilder(URI.create(BASE + "/api/v1/admin/mqtt/credentials"))
                .header("Content-Type", "application/json")
                .header("X-API-Key", System.getenv("IM_ADMIN_API_KEY"))
                .POST(HttpRequest.BodyPublishers.ofString(credentialJson))
                .build();
        HttpResponse<String> credentialResponse = client.send(createCredential, HttpResponse.BodyHandlers.ofString());
        System.out.println("credential: " + credentialResponse.statusCode() + " " + credentialResponse.body());

        // 3. 设备获取自己的 MQTT 配置（凭证用上一步返回的 password）
        HttpRequest deviceConfig = HttpRequest.newBuilder(URI.create(BASE + "/api/v1/device/mqtt/config"))
                .header("X-Device-Id", "device-001")
                .header("X-Device-Token", "<创建凭证返回的 password>")
                .GET()
                .timeout(Duration.ofSeconds(10))
                .build();
        HttpResponse<String> configResponse = client.send(deviceConfig, HttpResponse.BodyHandlers.ofString());
        System.out.println("device config: " + configResponse.statusCode() + " " + configResponse.body());
    }
}
```

管理接口推荐使用短生命周期的 `X-API-Key` 之外，生产环境优先接入平台 JWT：

```java
HttpRequest request = HttpRequest.newBuilder(URI.create(BASE + "/api/v1/admin/email/senders"))
        .header("Authorization", "Bearer " + accessToken)
        .header("Content-Type", "application/json")
        .GET()
        .build();
```
