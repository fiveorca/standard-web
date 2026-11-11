package com.platform.im.grpc;

import com.platform.im.application.EmailSendService;
import com.platform.im.application.MqttPublishService;
import com.platform.im.config.AppProperties;
import com.platform.im.domain.email.EmailTaskStatus;
import com.platform.im.domain.mqtt.MqttPublishRecord;
import com.platform.im.domain.mqtt.PublishStatus;
import com.platform.im.grpc.proto.email.EmailServiceGrpc;
import com.platform.im.grpc.proto.email.SendEmailRequest;
import com.platform.im.grpc.proto.mqtt.MqttMessageServiceGrpc;
import com.platform.im.grpc.proto.mqtt.PublishResponse;
import com.platform.im.grpc.proto.mqtt.PublishToDeviceRequest;
import com.platform.im.infrastructure.ratelimit.RequestRateLimiter;
import com.platform.im.security.JwtVerifier;
import com.platform.im.shared.ApiException;
import com.platform.im.web.dto.EmailDtos;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.ServerInterceptors;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GrpcServiceTest {
    private MqttPublishService mqttPublishService;
    private EmailSendService emailSendService;
    private Server server;
    private ManagedChannel channel;

    @BeforeEach
    void setUp() throws Exception {
        mqttPublishService = mock(MqttPublishService.class);
        emailSendService = mock(EmailSendService.class);
        AppProperties props = new AppProperties();
        props.grpc.authEnabled = false;
        GrpcAuthInterceptor auth = new GrpcAuthInterceptor(props, mock(JwtVerifier.class),
                mock(RequestRateLimiter.class));
        GrpcMetricsInterceptor metrics = new GrpcMetricsInterceptor(new SimpleMeterRegistry());
        String name = InProcessServerBuilder.generateName();
        server = InProcessServerBuilder.forName(name).directExecutor()
                .addService(ServerInterceptors.intercept(new MqttMessageGrpcService(mqttPublishService),
                        auth, metrics))
                .addService(ServerInterceptors.intercept(new EmailGrpcService(emailSendService),
                        auth, metrics))
                .build().start();
        channel = InProcessChannelBuilder.forName(name).directExecutor().build();
    }

    @AfterEach
    void tearDown() {
        channel.shutdownNow();
        server.shutdownNow();
    }

    @Test
    void publishesOverGrpcAndReturnsRecord() {
        MqttPublishRecord record = new MqttPublishRecord();
        record.id = UUID.randomUUID();
        record.messageId = "msg-1";
        record.topic = "devices/dev-1/up";
        record.deviceId = "dev-1";
        record.status = PublishStatus.PUBLISHED;
        when(mqttPublishService.publishToDevice(any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(new MqttPublishService.PublishOutcome(true, "0", "success", record, "dev-1"));

        PublishResponse response = MqttMessageServiceGrpc.newBlockingStub(channel).publishToDevice(
                PublishToDeviceRequest.newBuilder()
                        .setTenantId(UUID.randomUUID().toString())
                        .setDeviceId("dev-1")
                        .setMessageId("msg-1")
                        .setPayload(com.google.protobuf.ByteString.copyFromUtf8("hello"))
                        .setContentType("text/plain")
                        .setQos(1)
                        .build());

        assertTrue(response.getSuccess());
        assertEquals("0", response.getCode());
        assertEquals(record.id.toString(), response.getRecordId());
        assertEquals("devices/dev-1/up", response.getTopic());
    }

    @Test
    void mapsDomainErrorsToGrpcStatus() {
        when(mqttPublishService.publishToDevice(any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenThrow(ApiException.notFound("设备不存在"));

        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class,
                () -> MqttMessageServiceGrpc.newBlockingStub(channel).publishToDevice(
                        PublishToDeviceRequest.newBuilder()
                                .setDeviceId("dev-1")
                                .setMessageId("msg-1")
                                .setPayload(com.google.protobuf.ByteString.copyFromUtf8("hello"))
                                .build()));

        assertEquals(Status.Code.NOT_FOUND, exception.getStatus().getCode());
        assertTrue(exception.getStatus().getDescription().startsWith("40401:"));
    }

    @Test
    void acceptsEmailOverGrpc() {
        UUID taskId = UUID.randomUUID();
        when(emailSendService.accept(any())).thenReturn(
                new EmailSendService.AcceptedTask(taskId, "req-1", EmailTaskStatus.PENDING, true));

        var response = EmailServiceGrpc.newBlockingStub(channel).sendEmail(
                SendEmailRequest.newBuilder()
                        .setRequestId("req-1")
                        .addTo("user@example.com")
                        .setSubject("hello")
                        .setTextBody("body")
                        .build());

        assertTrue(response.getAccepted());
        assertEquals(taskId.toString(), response.getTaskId());
        assertEquals("PENDING", response.getStatus());
    }

    @Test
    void returnsEmailStatusOverGrpc() {
        UUID taskId = UUID.randomUUID();
        EmailDtos.EmailTaskView view = new EmailDtos.EmailTaskView(taskId, null, "req-1",
                UUID.randomUUID(), "hello", EmailTaskStatus.SUCCESS, 1, 3, null, null, null,
                "<msg@test>", Instant.parse("2026-01-01T00:00:00Z"), Instant.parse("2026-01-01T00:00:01Z"),
                Instant.parse("2026-01-01T00:00:02Z"), 10, Instant.parse("2026-01-01T00:00:00Z"),
                Instant.parse("2026-01-01T00:00:02Z"));
        when(emailSendService.status(any(), any(), any())).thenReturn(view);

        var response = EmailServiceGrpc.newBlockingStub(channel).getEmailStatus(
                com.platform.im.grpc.proto.email.GetEmailStatusRequest.newBuilder()
                        .setTaskId(taskId.toString())
                        .build());

        assertEquals("SUCCESS", response.getStatus());
        assertEquals("<msg@test>", response.getProviderMessageId());
        assertEquals(1, response.getAttempts());
        assertTrue(response.getFinishedAt().startsWith("2026-01-01"));
    }
}
