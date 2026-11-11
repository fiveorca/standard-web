# gRPC API

gRPC 用于平台内部业务服务调用，默认监听 `9090`，HTTP/2 明文或 TLS/mTLS。

Proto 契约：

- `src/main/proto/mqtt/mqtt_message_service.proto` → `platform.im.mqtt.v1`
- `src/main/proto/email/email_service.proto` → `platform.im.email.v1`

生成 Java 包：

- `com.platform.im.grpc.proto.mqtt`
- `com.platform.im.grpc.proto.email`

## 1. 认证

调用时在 metadata 中二选一：

| Key | 值 |
| --- | --- |
| `x-internal-token` | 与 `IM_INTERNAL_TOKEN` 一致 |
| `authorization` | `Bearer <JWT>`（`IM_GRPC_AUTH_ENABLED=true` 时校验） |

健康检查服务 `grpc.health.v1.Health` 无需认证。

JWT 中的租户与请求 `tenant_id` 不一致时返回 `PERMISSION_DENIED`。

## 2. TLS / mTLS

| 配置 | 说明 |
| --- | --- |
| `IM_GRPC_TLS_ENABLED=true` | 服务端启用 TLS |
| `IM_GRPC_CERT_CHAIN` | 服务端证书链 PEM 路径 |
| `IM_GRPC_PRIVATE_KEY` | 服务端私钥 PEM 路径 |
| `IM_GRPC_REQUIRE_CLIENT_AUTH=true` | 启用 mTLS |
| `IM_GRPC_TRUST_CERT` | 客户端 CA 证书 PEM 路径 |

生产环境建议开启 TLS；内部高安全场景开启 mTLS。

## 3. MqttMessageService

### 3.1 PublishToDevice

```protobuf
rpc PublishToDevice (PublishToDeviceRequest) returns (PublishResponse);

message PublishToDeviceRequest {
  string tenant_id = 1;
  string device_id = 2;
  string message_id = 3;
  bytes payload = 4;
  string content_type = 5;
  int32 qos = 6;
  bool retained = 7;
  uint32 message_expiry_interval = 8;
}
```

- `topic` 由服务端根据设备接入配置推导，调用方不可指定。
- `message_id` 为幂等键（同租户内唯一），重复调用返回已有发送记录。
- `qos` 为空/0 时使用接入配置默认 QoS；非法值返回 `INVALID_ARGUMENT`。
- `message_expiry_interval` 为秒，`0` 表示不设置。
- payload 超过 `IM_MQTT_MAX_PAYLOAD_BYTES` 返回 `RESOURCE_EXHAUSTED`。

响应：

```protobuf
message PublishResponse {
  bool success = 1;
  string code = 2;
  string message = 3;
  string record_id = 4;
  string topic = 5;
  string message_id = 6;
}
```

### 3.2 BatchPublishToDevices

```protobuf
rpc BatchPublishToDevices (BatchPublishToDevicesRequest) returns (BatchPublishResponse);
```

- `device_ids` 不能为空，单次最多 500 个。
- 每个设备独立记录结果，单个失败不影响其他设备。
- 幂等键为 `messageId#deviceId`。

```protobuf
message BatchPublishResponse {
  int32 total = 1;
  int32 success_count = 2;
  int32 failure_count = 3;
  repeated PublishResult results = 4;
}
```

### 3.3 PublishToTopic

```protobuf
rpc PublishToTopic (PublishToTopicRequest) returns (PublishResponse);
```

- 仅允许发布到服务端 ACL 授权的 Topic；未配置 SERVICE ACL 时要求 Topic 以 `serviceTopicPrefix`（默认 `tenants/`）开头。
- 不允许包含通配符。

## 4. EmailService

### 4.1 SendEmail

```protobuf
rpc SendEmail (SendEmailRequest) returns (EmailTaskResponse);

message SendEmailRequest {
  string request_id = 1;
  string sender_id = 2;
  string tenant_id = 3;
  repeated string to = 4;
  repeated string cc = 5;
  repeated string bcc = 6;
  string subject = 7;
  string text_body = 8;
  string html_body = 9;
  repeated EmailAttachment attachments = 10;
}
```

- `request_id` 为幂等键；重复请求返回已有任务（`message=idempotent_replay`）。
- `sender_id` 为空时使用租户默认发送方；未配置默认发送方返回 `UNAVAILABLE`。
- `text_body` 与 `html_body` 至少一个。
- 收件人总数不超过 `IM_EMAIL_MAX_RECIPIENTS`。
- 附件受类型、单文件大小、总大小限制。

响应：

```protobuf
message EmailTaskResponse {
  string task_id = 1;
  string status = 2;     // PENDING
  bool accepted = 3;
  string code = 4;       // "0"
  string message = 5;    // accepted / idempotent_replay
  string request_id = 6;
}
```

### 4.2 BatchSendEmail

```protobuf
rpc BatchSendEmail (BatchSendEmailRequest) returns (BatchSendEmailResponse);
```

- 单次最多 100 封。
- 返回每封邮件的受理结果。

### 4.3 GetEmailStatus

```protobuf
rpc GetEmailStatus (GetEmailStatusRequest) returns (EmailStatusResponse);

message GetEmailStatusRequest {
  string task_id = 1;
  string request_id = 2;
  string tenant_id = 3;
}
```

- `task_id` 与 `request_id` 至少提供一个。
- 返回 `status`、`attempts`、`last_error`、`provider_message_id`、`accepted_at`、`finished_at`。

## 5. 错误映射

服务端拦截器与业务异常统一映射为 gRPC Status，并通过 trailers 返回 `error-code`、`error-type`。

| 领域码 | HTTP | gRPC Status |
| --- | --- | --- |
| 40001 | 400 | `INVALID_ARGUMENT` |
| 40101 | 401 | `UNAUTHENTICATED` |
| 40301 | 403 | `PERMISSION_DENIED` |
| 40401 | 404 | `NOT_FOUND` |
| 40901 | 409 | `ALREADY_EXISTS` |
| 41301 | 413 | `RESOURCE_EXHAUSTED` |
| 42201 | 422 | `INVALID_ARGUMENT` |
| 42901 | 429 | `RESOURCE_EXHAUSTED` |
| 50201 | 502 | `UNAVAILABLE` |
| 50301 | 503 | `UNAVAILABLE` |
| 50001 | 500 | `INTERNAL` |

`Status.description` 格式为 `<code>:<message>`，例如 `42201:参数校验失败`。

## 6. 超时与重试

- 调用方必须设置 deadline：`stub.withDeadlineAfter(5, TimeUnit.SECONDS)`。
- 建议仅对 `UNAVAILABLE`、`DEADLINE_EXCEEDED` 做有限次退避重试。
- 写操作重试必须复用相同 `message_id` / `request_id`，服务端幂等保证不会重复发送。
- 服务端不主动重试 gRPC 发布；邮件发送由后台任务按策略重试。

## 7. Java 调用示例

### 7.1 依赖

服务端已生成并打包 Java Stub。其他 Java 服务推荐直接从 proto 生成，以保持契约独立：

```xml
<dependency>
    <groupId>io.grpc</groupId>
    <artifactId>grpc-netty-shaded</artifactId>
</dependency>
<dependency>
    <groupId>io.grpc</groupId>
    <artifactId>grpc-protobuf</artifactId>
</dependency>
<dependency>
    <groupId>io.grpc</groupId>
    <artifactId>grpc-stub</artifactId>
</dependency>
<dependency>
    <groupId>io.grpc</groupId>
    <artifactId>grpc-services</artifactId>
</dependency>
<dependency>
    <groupId>com.google.protobuf</groupId>
    <artifactId>protobuf-java</artifactId>
</dependency>
```

Protobuf 生成插件（与 im-service 一致）：

```xml
<plugin>
    <groupId>io.github.ascopes</groupId>
    <artifactId>protobuf-maven-plugin</artifactId>
    <version>5.1.11</version>
    <configuration>
        <protoc kind="binary-maven">
            <version>4.36.2</version>
        </protoc>
        <plugins>
            <plugin kind="binary-maven">
                <groupId>io.grpc</groupId>
                <artifactId>protoc-gen-grpc-java</artifactId>
                <version>1.84.1</version>
            </plugin>
        </plugins>
    </configuration>
    <executions>
        <execution>
            <goals><goal>generate</goal></goals>
        </execution>
    </executions>
</plugin>
```

将 `mqtt_message_service.proto`、`email_service.proto` 放入调用方的 `src/main/proto/` 下即可生成同名 Java 类型。

### 7.2 发布 MQTT 消息

```java
import com.platform.im.grpc.proto.mqtt.MqttMessageServiceGrpc;
import com.platform.im.grpc.proto.mqtt.PublishToDeviceRequest;
import com.platform.im.grpc.proto.mqtt.PublishResponse;
import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.stub.MetadataUtils;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class MqttPublishExample {
    public static void main(String[] args) {
        ManagedChannel channel = ManagedChannelBuilder.forAddress("localhost", 9090)
                .usePlaintext()                 // 生产环境改为 useTransportSecurity()
                .build();
        try {
            Metadata headers = new Metadata();
            headers.put(Metadata.Key.of("x-internal-token", Metadata.ASCII_STRING_MARSHALLER),
                    System.getenv("IM_INTERNAL_TOKEN"));

            MqttMessageServiceGrpc.MqttMessageServiceBlockingStub stub =
                    MqttMessageServiceGrpc.newBlockingStub(channel)
                            .withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers))
                            .withDeadlineAfter(5, TimeUnit.SECONDS);

            PublishResponse response = stub.publishToDevice(
                    PublishToDeviceRequest.newBuilder()
                            .setTenantId("")
                            .setDeviceId("device-001")
                            .setMessageId(UUID.randomUUID().toString())
                            .setPayload(ByteString.copyFromUtf8("{\"cmd\":\"reboot\"}"))
                            .setContentType("application/json")
                            .setQos(1)
                            .setRetained(false)
                            .build());

            System.out.println("success=" + response.getSuccess()
                    + " recordId=" + response.getRecordId()
                    + " topic=" + response.getTopic());
        } finally {
            channel.shutdownNow();
        }
    }
}
```

### 7.3 发送邮件

```java
import com.platform.im.grpc.proto.email.EmailServiceGrpc;
import com.platform.im.grpc.proto.email.EmailTaskResponse;
import com.platform.im.grpc.proto.email.SendEmailRequest;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.stub.MetadataUtils;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class EmailSendExample {
    public static void main(String[] args) {
        ManagedChannel channel = ManagedChannelBuilder.forAddress("localhost", 9090)
                .usePlaintext()
                .build();
        try {
            Metadata headers = new Metadata();
            headers.put(Metadata.Key.of("x-internal-token", Metadata.ASCII_STRING_MARSHALLER),
                    System.getenv("IM_INTERNAL_TOKEN"));

            EmailServiceGrpc.EmailServiceBlockingStub stub =
                    EmailServiceGrpc.newBlockingStub(channel)
                            .withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers))
                            .withDeadlineAfter(10, TimeUnit.SECONDS);

            EmailTaskResponse response = stub.sendEmail(
                    SendEmailRequest.newBuilder()
                            .setRequestId("order-20260101-0001")
                            .setSenderId("")                       // 空表示默认发送方
                            .addTo("user@example.com")
                            .setSubject("订单已发货")
                            .setTextBody("您的订单已发货。")
                            .setHtmlBody("<p>您的订单已发货。</p>")
                            .build());

            System.out.println("taskId=" + response.getTaskId()
                    + " status=" + response.getStatus()
                    + " message=" + response.getMessage());
        } finally {
            channel.shutdownNow();
        }
    }
}
```

### 7.4 健康检查

```java
import io.grpc.health.v1.HealthCheckRequest;
import io.grpc.health.v1.HealthCheckResponse;
import io.grpc.health.v1.HealthGrpc;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

public class HealthExample {
    public static void main(String[] args) {
        ManagedChannel channel = ManagedChannelBuilder.forAddress("localhost", 9090)
                .usePlaintext()
                .build();
        try {
            HealthCheckResponse response = HealthGrpc.newBlockingStub(channel)
                    .check(HealthCheckRequest.newBuilder()
                            .setService("platform.im.mqtt.v1.MqttMessageService")
                            .build());
            System.out.println("serving=" + (response.getStatus() == HealthCheckResponse.ServingStatus.SERVING));
        } finally {
            channel.shutdownNow();
        }
    }
}
```

### 7.5 TLS / mTLS 客户端

TLS（校验服务端证书，使用 JVM 默认信任库）：

```java
ManagedChannel channel = ManagedChannelBuilder.forAddress("im-service", 9090)
        .useTransportSecurity()
        .build();
```

mTLS 需要显式构建 `SslContext`（使用 `grpc-netty` / `grpc-netty-shaded` 的 `GrpcSslContexts`）：

```java
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;

ManagedChannel channel = NettyChannelBuilder.forAddress("im-service", 9090)
        .sslContext(GrpcSslContexts.forClient()
                .trustManager(new java.io.File("ca.pem"))
                .keyManager(new java.io.File("client-cert.pem"), new java.io.File("client-key.pem"))
                .build())
        .build();
```

## 8. 契约变更规范

- 新增字段使用新编号，禁止复用或修改已发布字段编号。
- 删除字段使用 `reserved`。
- 破坏性变更升级 package 版本（例如 `platform.im.mqtt.v2`），保持旧版本并行。
