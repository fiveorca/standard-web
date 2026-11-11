package com.platform.im.application;

import com.platform.im.config.AppProperties;
import com.platform.im.domain.mqtt.MqttAccessConfig;
import com.platform.im.domain.mqtt.MqttBroker;
import com.platform.im.domain.mqtt.MqttDeviceCredential;
import com.platform.im.domain.mqtt.MqttPublishRecord;
import com.platform.im.domain.mqtt.PublishStatus;
import com.platform.im.domain.repository.MqttBrokerRepository;
import com.platform.im.domain.repository.MqttPublishRecordRepository;
import com.platform.im.domain.repository.MqttTopicAclRepository;
import com.platform.im.infrastructure.mqtt.MqttMetrics;
import com.platform.im.infrastructure.mqtt.MqttPublisher;
import com.platform.im.shared.ApiException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class MqttPublishServiceTest {
    private static final UUID TENANT = UUID.randomUUID();

    private MqttPublishRecordRepository recordRepository;
    private MqttDeviceCredentialService credentialService;
    private MqttPublishService service;
    private MqttPublisher publisher;
    private MqttDeviceCredential credential;
    private MqttBroker broker;

    @BeforeEach
    void setUp() {
        recordRepository = mock(MqttPublishRecordRepository.class);
        credentialService = mock(MqttDeviceCredentialService.class);
        MqttAccessConfigService accessConfigService = mock(MqttAccessConfigService.class);
        MqttBrokerRepository brokerRepository = mock(MqttBrokerRepository.class);
        MqttTopicAclRepository aclRepository = mock(MqttTopicAclRepository.class);
        publisher = mock(MqttPublisher.class);
        MqttMetrics metrics = mock(MqttMetrics.class);

        AppProperties props = new AppProperties();
        props.mqtt.maxPayloadBytes = 64;
        props.mqtt.serviceTopicPrefix = "tenants/";
        service = new MqttPublishService(recordRepository, credentialService, accessConfigService,
                brokerRepository, aclRepository, publisher, metrics, props);

        MqttAccessConfig config = new MqttAccessConfig();
        config.id = UUID.randomUUID();
        config.publishTopicTemplate = "devices/{deviceId}/up";
        config.defaultQos = 1;
        config.retainDefault = false;
        config.messageExpiryIntervalSeconds = 0;

        broker = new MqttBroker();
        broker.id = UUID.randomUUID();
        broker.enabled = true;

        credential = new MqttDeviceCredential();
        credential.id = UUID.randomUUID();
        credential.tenantId = TENANT;
        credential.deviceId = "dev-1";
        credential.status = com.platform.im.domain.mqtt.CredentialStatus.ACTIVE;

        when(credentialService.requireForPublish(TENANT, "dev-1")).thenReturn(credential);
        when(credentialService.contextFor(credential))
                .thenReturn(new MqttDeviceCredentialService.Context(config, broker));
        when(credentialService.variables(credential)).thenReturn(Map.of("deviceId", "dev-1"));
        when(credentialService.authorizePublish(credential, "devices/dev-1/up")).thenReturn(true);
        when(recordRepository.save(any(MqttPublishRecord.class))).thenAnswer(invocation -> {
            MqttPublishRecord record = invocation.getArgument(0);
            if (record.id == null) {
                record.id = UUID.randomUUID();
            }
            return record;
        });
    }

    @Test
    void publishesToResolvedDeviceTopicAndMarksPublished() {
        when(recordRepository.findByTenantIdAndMessageId(TENANT, "msg-1")).thenReturn(Optional.empty());

        MqttPublishService.PublishOutcome outcome = service.publishToDevice(
                TENANT, "dev-1", "msg-1", "hello".getBytes(), "text/plain", 2, true, 30L, "GRPC");

        assertTrue(outcome.success());
        assertEquals(PublishStatus.PUBLISHED, outcome.record().status);
        assertEquals("devices/dev-1/up", outcome.record().topic);
        assertEquals(2, outcome.record().qos);
        assertTrue(outcome.record().retained);
        assertEquals(30L, outcome.record().messageExpiryIntervalSeconds);
        verify(publisher).publish(broker, "devices/dev-1/up", "hello".getBytes(), 2, true, 30L);
    }

    @Test
    void returnsExistingRecordForIdempotentReplay() {
        MqttPublishRecord existing = new MqttPublishRecord();
        existing.id = UUID.randomUUID();
        existing.messageId = "msg-1";
        existing.deviceId = "dev-1";
        existing.topic = "devices/dev-1/up";
        existing.status = PublishStatus.PUBLISHED;
        when(recordRepository.findByTenantIdAndMessageId(TENANT, "msg-1")).thenReturn(Optional.of(existing));

        MqttPublishService.PublishOutcome outcome = service.publishToDevice(
                TENANT, "dev-1", "msg-1", "hello".getBytes(), "text/plain", 1, false, null, "GRPC");

        assertTrue(outcome.success());
        assertEquals("0", outcome.code());
        verify(publisher, never()).publish(any(), anyString(), any(), anyInt(), anyBoolean(), anyLong());
        verify(recordRepository, never()).save(any());
    }

    @Test
    void rejectsWhenDeviceAclDeniesPublish() {
        when(recordRepository.findByTenantIdAndMessageId(TENANT, "msg-2")).thenReturn(Optional.empty());
        when(credentialService.authorizePublish(credential, "devices/dev-1/up")).thenReturn(false);

        ApiException exception = assertThrows(ApiException.class, () -> service.publishToDevice(
                TENANT, "dev-1", "msg-2", "hello".getBytes(), "text/plain", 1, false, null, "GRPC"));

        assertEquals(403, exception.status());
        verify(recordRepository, never()).save(any());
        verify(publisher, never()).publish(any(), anyString(), any(), anyInt(), anyBoolean(), anyLong());
    }

    @Test
    void rejectsPayloadOverLimit() {
        byte[] payload = new byte[65];
        ApiException exception = assertThrows(ApiException.class, () -> service.publishToDevice(
                TENANT, "dev-1", "msg-3", payload, "text/plain", 1, false, null, "GRPC"));
        assertEquals(413, exception.status());
    }

    @Test
    void marksRecordFailedWhenBrokerPublishFails() {
        when(recordRepository.findByTenantIdAndMessageId(TENANT, "msg-4")).thenReturn(Optional.empty());
        org.mockito.Mockito.doThrow(new com.platform.im.infrastructure.mqtt.MqttPublishException(
                        "MQTT_UNAVAILABLE", "broker down"))
                .when(publisher).publish(any(), anyString(), any(), anyInt(), anyBoolean(), anyLong());

        MqttPublishService.PublishOutcome outcome = service.publishToDevice(
                TENANT, "dev-1", "msg-4", "hello".getBytes(), "text/plain", 1, false, null, "GRPC");

        assertFalse(outcome.success());
        assertEquals(PublishStatus.FAILED, outcome.record().status);
        assertEquals("MQTT_UNAVAILABLE", outcome.record().errorCode);
    }

    @Test
    void batchPublishesEachDeviceIndependently() {
        when(recordRepository.findByTenantIdAndMessageId(eq(TENANT), anyString())).thenReturn(Optional.empty());

        MqttPublishService.BatchOutcome outcome = service.batchPublishToDevices(
                TENANT, java.util.List.of("dev-1"), "batch-1", "hello".getBytes(),
                "text/plain", 1, false, null, "GRPC");

        assertEquals(1, outcome.total());
        assertEquals(1, outcome.successCount());
        ArgumentCaptor<MqttPublishRecord> captor = ArgumentCaptor.forClass(MqttPublishRecord.class);
        verify(recordRepository, org.mockito.Mockito.atLeastOnce()).save(captor.capture());
        assertEquals("batch-1#dev-1", captor.getValue().messageId);
    }
}
