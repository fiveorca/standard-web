# MQTT 接入与权限

## 1. 角色与连接方式

| 角色 | 连接对象 | 说明 |
| --- | --- | --- |
| im-service | MQTT Broker | 作为发布客户端，为平台服务发布设备消息 |
| 终端设备 | MQTT Broker | 直接连接 Broker，不经过 im-service 转发 |
| EMQX | im-service HTTP | 通过 HTTP 认证/ACL 回调校验设备 |

im-service 不会代理设备的 MQTT 流量。设备消息链路由 Broker 保证，服务只负责凭证、配置和 ACL 下发。

## 2. Broker 与 EMQX 配置

`docker/emqx/emqx.conf` 已配置：

- TCP 监听 `1883`
- Dashboard `18083`
- HTTP 认证：`POST http://im-service:8080/api/v1/internal/mqtt/auth`
- HTTP 授权：`POST http://im-service:8080/api/v1/internal/mqtt/acl`
- `no_match = deny`，默认拒绝未命中规则
- `deny_action = ignore`：未授权消息被 Broker 丢弃，MQTT 客户端可能仍收到成功 ACK
- ACL 缓存 1 分钟

认证/授权回调显式设置 `Content-Type: application/json`；服务端内部接口同时兼容
`application/x-www-form-urlencoded`，便于不同 EMQX 版本或自定义配置接入。

EMQX HTTP 数据源在启动时解析 `im-service` 主机名，若 im-service 尚未就绪会短暂进入
resource down，之后按内置间隔自动重试恢复，无需重启 EMQX。

> `X-Internal-Token` 必须与 `IM_INTERNAL_TOKEN` 一致；修改任一侧后需同时更新并重启 EMQX。

生产环境应额外配置：

- MQTT TLS 监听（8883）与证书
- Dashboard 强密码、关闭公网访问
- 集群与持久化
- 按需限制连接数、消息大小、速率

Broker 配置也可以通过管理 API 维护（支持多 Broker、默认 Broker、启停、测试连接）。接入配置绑定具体 Broker，设备配置由接入配置推导。

## 3. 设备身份认证

### 3.1 凭证模式（默认 `CREDENTIAL`）

1. 管理端创建凭证，服务生成随机用户名与 32 字节随机密码。
2. 响应返回一次明文密码；数据库保存：
   - `password_hash`：SHA-256 + `IM_DEVICE_TOKEN_PEPPER`
   - `password_cipher`：AES-256-GCM 密文（用于设备配置下发）
3. 设备用 `username` + `password` 连接 Broker。
4. EMQX 调用 `/api/v1/internal/mqtt/auth`，服务校验摘要与凭证状态（ACTIVE、未过期）。

### 3.2 平台 JWT 模式（`PLATFORM_JWT`）

设备也可以使用平台 JWT 调用设备 HTTP 接口获取配置；JWT 需包含 `device_id` claim（可通过 `IM_JWT_*` 配置 claim 名称）。MQTT 连接本身仍使用服务下发的用户名/密码，以免把用户体系引入 Broker。

### 3.3 凭证生命周期

| 操作 | 行为 |
| --- | --- |
| 创建 | 生成用户名/密码，默认创建 PUBLISH/SUBSCRIBE 两条 ACL，`configVersion=1` |
| 轮换 | 重新生成密码，状态恢复 ACTIVE，`configVersion+1`，返回新密码 |
| 禁用 | 状态 DISABLED，`configVersion+1`，认证立即失败（受 EMQX ACL 缓存影响最多 1 分钟） |
| 撤销 | 状态 REVOKED，密码摘要与密文随机化，不可恢复、不可轮换 |
| 过期 | `expires_at` 到期后认证失败 |

设备通过 `GET /api/v1/device/mqtt/config/version` 比较本地版本，发现变化后重新拉取配置。

## 4. Topic 规则

### 4.1 模板

接入配置默认：

```text
publishTopicTemplate   = devices/{deviceId}/up
subscribeTopicTemplate = devices/{deviceId}/down
serviceTopicPrefix     = tenants/
```

支持变量：`{deviceId}`、`{tenantId}`。例如设备 `device-001`：

- 上行：`devices/device-001/up`
- 下行：`devices/device-001/down`

### 4.2 ACL 语义

- 主体：`DEVICE`（按 `deviceId`）或 `SERVICE`（按服务标识）
- 动作：`PUBLISH` / `SUBSCRIBE`
- 效果：`ALLOW` / `DENY`
- 匹配：MQTT 通配符 `+`（单级）、`#`（多级，只能在末尾）
- 订阅授权使用“覆盖”判断：授权规则必须覆盖请求的 Topic Filter，禁止设备订阅比授权更宽的范围（例如授权 `devices/a/down` 不允许订阅 `devices/+/down`）
- 按 `priority` 降序匹配；命中 `DENY` 立即拒绝，否则任一 `ALLOW` 命中即允许
- 未命中任何规则：拒绝（EMQX `no_match = deny`）
- 发布 Topic 不允许包含通配符

默认 ACL（创建凭证时自动生成）：

| 动作 | Topic | 效果 |
| --- | --- | --- |
| PUBLISH | `devices/{deviceId}/up` | ALLOW |
| SUBSCRIBE | `devices/{deviceId}/down` | ALLOW |

> 默认只允许精确 Topic。若设备需要订阅多个子 Topic，请追加 ACL，例如 `devices/device-001/commands/#`。

### 4.3 平台服务发布授权

- `PublishToDevice`：Topic 由接入配置推导，并校验设备 PUBLISH ACL（未配置 ACL 时仅允许模板推导 Topic）。
- `PublishToTopic`：优先匹配 `SERVICE` ACL；未配置 SERVICE ACL 时仅允许以 `serviceTopicPrefix` 开头的 Topic。
- 普通业务服务不能任意指定未授权 Topic。

## 5. 设备获取配置

```http
GET /api/v1/device/mqtt/config
X-Device-Id: device-001
X-Device-Token: <password>
```

返回字段：

| 字段 | 说明 |
| --- | --- |
| `brokerUrl` | `tcp://host` 或 `ssl://host` |
| `port` | TCP 或 TLS 端口 |
| `protocolVersion` | `5.0` |
| `tlsEnabled` | 是否 TLS |
| `clientId` | 建议 Client ID（当前等于 MQTT 用户名） |
| `username` / `password` | MQTT 凭证 |
| `keepAlive` | Keep Alive 秒 |
| `cleanStart` | Clean Start |
| `sessionExpiry` | Session Expiry 秒 |
| `defaultQos` | 默认 QoS |
| `publishTopic` / `subscribeTopic` | 模板解析后的 Topic |
| `topicPermissions` | 设备 ACL 列表（含 `qosMax`） |
| `configVersion` | 设备凭证配置版本 |
| `accessConfigVersion` | 接入配置版本 |
| `expiresAt` | 凭证过期时间 |

## 6. MQTT 5.0 参数建议

| 场景 | cleanStart | sessionExpiry | 说明 |
| --- | --- | --- | --- |
| 临时设备 | `true` | `0` | 断开即清理会话 |
| 需要离线消息 | `false` | `>0`（如 86400） | Broker 保留会话与订阅，离线期间 QoS 1/2 消息可缓存 |
| 只上报 | `true` | `0` | 简化状态管理 |

- QoS：0 最多一次、1 至少一次、2 恰好一次（协议层）。
- Retained：设备状态类消息可使用，注意清理旧状态。
- Message Expiry Interval：离线消息过期时间，避免过期指令被消费。
- Keep Alive：建议 30–120 秒，需与网络环境匹配。

## 7. 设备端 Java 示例（Eclipse Paho MQTT v5）

```java
import org.eclipse.paho.mqttv5.client.MqttClient;
import org.eclipse.paho.mqttv5.client.MqttConnectionOptions;
import org.eclipse.paho.mqttv5.client.persist.MemoryPersistence;
import org.eclipse.paho.mqttv5.common.MqttMessage;
import org.eclipse.paho.mqttv5.common.packet.MqttProperties;

import java.nio.charset.StandardCharsets;

public class DeviceMqttExample {
    public static void main(String[] args) throws Exception {
        String brokerUrl = "tcp://localhost";     // TLS 时使用 ssl://
        int port = 1883;
        String clientId = "device-001";
        String username = "dev_xxx";
        String password = "创建凭证时返回的密码";
        String publishTopic = "devices/device-001/up";
        String subscribeTopic = "devices/device-001/down";

        MqttClient client = new MqttClient(brokerUrl + ":" + port, clientId, new MemoryPersistence());

        MqttConnectionOptions options = new MqttConnectionOptions();
        options.setUserName(username);
        options.setPassword(password.getBytes(StandardCharsets.UTF_8));
        options.setKeepAliveInterval(60);
        options.setCleanStart(true);
        options.setSessionExpiryInterval(0L);
        options.setAutomaticReconnect(true);

        client.connect(options);
        client.subscribe(subscribeTopic, 1, (topic, message) ->
                System.out.println("downlink " + topic + " -> " + new String(message.getPayload(), StandardCharsets.UTF_8)));

        MqttMessage message = new MqttMessage("{\"temperature\":26.5}".getBytes(StandardCharsets.UTF_8));
        message.setQos(1);
        message.setRetained(false);
        MqttProperties properties = new MqttProperties();
        properties.setMessageExpiryInterval(3600L);
        message.setProperties(properties);
        client.publish(publishTopic, message);

        client.disconnect();
        client.close();
    }
}
```

## 8. 交付确认语义（重要）

MQTT QoS 1/2 只保证 Broker 与设备之间的协议交付，**不代表设备业务逻辑已处理消息**。

如需业务确认：

1. 设备处理完成后发布 ACK 到约定 Topic，例如 `devices/{deviceId}/ack`。
2. 平台服务订阅 ACK 并关联 `messageId`。
3. 在 `mqtt_publish_record` 基础上扩展业务确认状态（当前已预留 `message_id`、`source`、`trace_id`，可按需新增确认表）。

## 9. 排查清单

| 现象 | 排查方向 |
| --- | --- |
| 设备连接被拒绝 | 凭证状态、过期时间、密码是否被轮换；EMQX 日志中的 HTTP 回调结果 |
| 发布被拒绝 | Topic 是否与 ACL 匹配；是否命中 DENY；是否包含通配符 |
| 订阅被拒绝 | 请求 Filter 是否比授权规则更宽；`covers` 规则 |
| 设备收不到下行消息 | Session Expiry / Clean Start 配置；QoS；Retained；消息过期时间 |
| 平台发布失败 | Broker 状态、发送记录错误码、网络与认证配置 |
| 配置未更新 | 比较 `configVersion` / `accessConfigVersion`；EMQX ACL 缓存 TTL |
