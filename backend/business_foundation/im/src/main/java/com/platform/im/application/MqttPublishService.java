package com.platform.im.application;

import com.platform.im.config.AppProperties;
import com.platform.im.domain.mqtt.AclAction;
import com.platform.im.domain.mqtt.AclEffect;
import com.platform.im.domain.mqtt.AclSubjectType;
import com.platform.im.domain.mqtt.MqttAccessConfig;
import com.platform.im.domain.mqtt.MqttBroker;
import com.platform.im.domain.mqtt.MqttDeviceCredential;
import com.platform.im.domain.mqtt.MqttPublishRecord;
import com.platform.im.domain.mqtt.MqttTopicAcl;
import com.platform.im.domain.mqtt.PublishStatus;
import com.platform.im.domain.mqtt.TopicRules;
import com.platform.im.domain.repository.MqttBrokerRepository;
import com.platform.im.domain.repository.MqttPublishRecordRepository;
import com.platform.im.domain.repository.MqttTopicAclRepository;
import com.platform.im.infrastructure.mqtt.MqttMetrics;
import com.platform.im.infrastructure.mqtt.MqttPublishException;
import com.platform.im.infrastructure.mqtt.MqttPublisher;
import com.platform.im.shared.ApiException;
import com.platform.im.shared.CryptoService;
import com.platform.im.shared.Ids;
import com.platform.im.shared.PageQuery;
import com.platform.im.shared.PageResult;
import com.platform.im.web.dto.MqttDtos;
import org.slf4j.MDC;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * MQTT 消息发布编排：身份/ACL 校验、消息记录、幂等与 Broker 发布。
 */
@Service
public class MqttPublishService {
    private static final int MAX_BATCH = 200;

    private final MqttPublishRecordRepository recordRepository;
    private final MqttDeviceCredentialService credentialService;
    private final MqttAccessConfigService accessConfigService;
    private final MqttBrokerRepository brokerRepository;
    private final MqttTopicAclRepository aclRepository;
    private final MqttPublisher publisher;
    private final MqttMetrics metrics;
    private final AppProperties props;

    public MqttPublishService(MqttPublishRecordRepository recordRepository,
                              MqttDeviceCredentialService credentialService,
                              MqttAccessConfigService accessConfigService,
                              MqttBrokerRepository brokerRepository,
                              MqttTopicAclRepository aclRepository,
                              MqttPublisher publisher,
                              MqttMetrics metrics,
                              AppProperties props) {
        this.recordRepository = recordRepository;
        this.credentialService = credentialService;
        this.accessConfigService = accessConfigService;
        this.brokerRepository = brokerRepository;
        this.aclRepository = aclRepository;
        this.publisher = publisher;
        this.metrics = metrics;
        this.props = props;
    }

    public PublishOutcome publishToDevice(UUID tenantId, String deviceId, String messageId,
                                          byte[] payload, String contentType, Integer qos,
                                          Boolean retained, Long messageExpiryInterval,
                                          String source) {
        validatePayload(payload);
        TopicRules.validateDeviceId(deviceId);
        String resolvedMessageId = normalizeMessageId(messageId);
        PublishOutcome replay = findReplay(tenantId, resolvedMessageId);
        if (replay != null) {
            return replay;
        }
        MqttDeviceCredential credential = credentialService.requireForPublish(tenantId, deviceId);
        MqttDeviceCredentialService.Context context = credentialService.contextFor(credential);
        String topic = TopicRules.resolve(context.config().publishTopicTemplate,
                credentialService.variables(credential));
        if (!credentialService.authorizePublish(credential, topic)) {
            throw ApiException.forbidden("设备未授权接收该 Topic 的消息");
        }
        return doPublish(tenantId == null ? credential.tenantId : tenantId, credential.deviceId,
                resolvedMessageId, topic, context.broker(), payload, contentType, qos, retained,
                messageExpiryInterval, context.config(), source);
    }

    public BatchOutcome batchPublishToDevices(UUID tenantId, List<String> deviceIds, String messageId,
                                              byte[] payload, String contentType, Integer qos,
                                              Boolean retained, Long messageExpiryInterval,
                                              String source) {
        if (deviceIds == null || deviceIds.isEmpty()) {
            throw ApiException.validation("device_ids", "设备列表不能为空");
        }
        if (deviceIds.size() > MAX_BATCH) {
            throw ApiException.validation("device_ids", "单次批量最多 " + MAX_BATCH + " 个设备");
        }
        validatePayload(payload);
        String baseMessageId = normalizeMessageId(messageId);
        List<PublishOutcome> results = new ArrayList<>(deviceIds.size());
        int success = 0;
        for (String deviceId : deviceIds) {
            String perDeviceMessageId = baseMessageId + "#" + deviceId;
            try {
                PublishOutcome outcome = publishToDevice(tenantId, deviceId, perDeviceMessageId,
                        payload, contentType, qos, retained, messageExpiryInterval, source);
                results.add(outcome);
                if (outcome.success()) {
                    success++;
                }
            } catch (ApiException ex) {
                results.add(new PublishOutcome(false, String.valueOf(ex.code()), ex.getMessage(), null, deviceId));
            } catch (RuntimeException ex) {
                results.add(new PublishOutcome(false, "50001", "消息发布失败: " + ex.getMessage(), null, deviceId));
            }
        }
        return new BatchOutcome(results.size(), success, results.size() - success, results);
    }

    public PublishOutcome publishToTopic(UUID tenantId, String topic, String messageId,
                                         byte[] payload, String contentType, Integer qos,
                                         Boolean retained, Long messageExpiryInterval,
                                         String source) {
        validatePayload(payload);
        TopicRules.validatePublishTopic(topic);
        String resolvedMessageId = normalizeMessageId(messageId);
        PublishOutcome replay = findReplay(tenantId, resolvedMessageId);
        if (replay != null) {
            return replay;
        }
        MqttAccessConfig config = accessConfigService.resolveDefault(tenantId);
        MqttBroker broker = brokerRepository.findById(config.brokerId)
                .orElseThrow(() -> ApiException.unavailable("MQTT Broker 不存在"));
        if (!broker.enabled) {
            throw ApiException.unavailable("MQTT Broker 已禁用");
        }
        authorizeServiceTopic(config, tenantId, topic);
        return doPublish(tenantId, null, resolvedMessageId, topic, broker, payload, contentType, qos,
                retained, messageExpiryInterval, config, source);
    }

    public PageResult<MqttDtos.PublishRecordView> list(Integer page, Integer size, String tenantId,
                                                       String deviceId, PublishStatus status) {
        PageQuery query = PageQuery.of(page, size);
        Sort sort = Sort.by(Sort.Direction.DESC, "createdAt");
        UUID tenant = Ids.parseUuid(tenantId, "tenant_id");
        String device = deviceId == null || deviceId.isBlank() ? null : deviceId.trim();
        Page<MqttPublishRecord> result;
        if (tenant != null && status != null && device != null) {
            result = recordRepository.findByTenantIdAndStatusAndDeviceId(tenant, status, device, query.pageable(sort));
        } else if (tenant != null && status != null) {
            result = recordRepository.findByTenantIdAndStatus(tenant, status, query.pageable(sort));
        } else if (tenant != null && device != null) {
            result = recordRepository.findByTenantIdAndDeviceId(tenant, device, query.pageable(sort));
        } else if (tenant != null) {
            result = recordRepository.findByTenantId(tenant, query.pageable(sort));
        } else if (status != null && device != null) {
            result = recordRepository.findByStatusAndDeviceId(status, device, query.pageable(sort));
        } else if (status != null) {
            result = recordRepository.findByStatus(status, query.pageable(sort));
        } else if (device != null) {
            result = recordRepository.findByDeviceId(device, query.pageable(sort));
        } else {
            result = recordRepository.findAll(query.pageable(sort));
        }
        return PageResult.of(result, this::toView);
    }

    public MqttDtos.PublishRecordView get(UUID id, String tenantId) {
        UUID tenant = Ids.parseUuid(tenantId, "tenant_id");
        MqttPublishRecord record = tenant == null
                ? recordRepository.findById(id).orElseThrow(() -> ApiException.notFound("消息发送记录不存在"))
                : recordRepository.findByIdAndTenantId(id, tenant)
                .orElseThrow(() -> ApiException.notFound("消息发送记录不存在"));
        return toView(record);
    }

    public MqttDtos.PublishRecordView toView(MqttPublishRecord record) {
        return new MqttDtos.PublishRecordView(record.id, record.tenantId, record.messageId, record.deviceId,
                record.topic, record.contentType, record.payloadSize, record.qos, record.retained,
                record.messageExpiryIntervalSeconds, record.status, record.brokerId, record.errorCode,
                record.errorMessage, record.traceId, record.publishedAt, record.createdAt);
    }

    private PublishOutcome doPublish(UUID tenantId, String deviceId, String messageId, String topic,
                                     MqttBroker broker, byte[] payload, String contentType, Integer qos,
                                     Boolean retained, Long messageExpiryInterval,
                                     MqttAccessConfig config, String source) {
        int resolvedQos = TopicRules.normalizeQos(qos == null ? config.defaultQos : qos, config.defaultQos, 2);
        boolean resolvedRetained = retained == null ? config.retainDefault : retained;
        long expiry = messageExpiryInterval == null
                ? config.messageExpiryIntervalSeconds : Math.max(0, messageExpiryInterval);

        MqttPublishRecord record = new MqttPublishRecord();
        record.tenantId = tenantId;
        record.messageId = messageId;
        record.deviceId = deviceId;
        record.topic = topic;
        record.contentType = contentType == null || contentType.isBlank()
                ? "application/octet-stream" : contentType.trim();
        record.payloadHash = CryptoService.sha256Base64(payload);
        record.payloadSize = payload.length;
        record.qos = resolvedQos;
        record.retained = resolvedRetained;
        record.messageExpiryIntervalSeconds = expiry;
        record.status = PublishStatus.PENDING;
        record.brokerId = broker.id;
        record.traceId = MDC.get("traceId");
        record.source = source == null || source.isBlank() ? "GRPC" : source;
        try {
            record = recordRepository.save(record);
        } catch (DataIntegrityViolationException duplicate) {
            PublishOutcome replay = findReplay(tenantId, messageId);
            if (replay != null) {
                return replay;
            }
            throw duplicate;
        }

        long start = System.nanoTime();
        try {
            publisher.publish(broker, topic, payload, resolvedQos, resolvedRetained, expiry);
            record.status = PublishStatus.PUBLISHED;
            record.publishedAt = Instant.now();
            MqttPublishRecord saved = recordRepository.save(record);
            metrics.recordSuccess(System.nanoTime() - start);
            return new PublishOutcome(true, "0", "success", saved, deviceId);
        } catch (MqttPublishException ex) {
            record.status = PublishStatus.FAILED;
            record.errorCode = ex.code();
            record.errorMessage = truncate(ex.getMessage(), 1024);
            MqttPublishRecord saved = recordRepository.save(record);
            metrics.recordFailure(System.nanoTime() - start);
            return new PublishOutcome(false, ex.code(), ex.getMessage(), saved, deviceId);
        } catch (RuntimeException ex) {
            record.status = PublishStatus.FAILED;
            record.errorCode = "MQTT_PUBLISH_FAILED";
            record.errorMessage = truncate(ex.getClass().getSimpleName() + ": " + ex.getMessage(), 1024);
            MqttPublishRecord saved = recordRepository.save(record);
            metrics.recordFailure(System.nanoTime() - start);
            return new PublishOutcome(false, "MQTT_PUBLISH_FAILED", ex.getMessage(), saved, deviceId);
        }
    }

    private PublishOutcome findReplay(UUID tenantId, String messageId) {
        var existing = tenantId == null
                ? recordRepository.findFirstByTenantIdIsNullAndMessageId(messageId)
                : recordRepository.findByTenantIdAndMessageId(tenantId, messageId);
        return existing.map(record -> new PublishOutcome(
                record.status == PublishStatus.PUBLISHED,
                record.status == PublishStatus.PUBLISHED ? "0" : "40901",
                record.status == PublishStatus.PUBLISHED
                        ? "消息已发布（幂等重放）"
                        : "相同 messageId 的消息正在处理或已失败: " + record.status,
                record,
                record.deviceId)).orElse(null);
    }

    private void authorizeServiceTopic(MqttAccessConfig config, UUID tenantId, String topic) {
        List<MqttTopicAcl> acls = aclRepository
                .findByAccessConfigIdAndSubjectTypeAndActionAndEnabledTrueOrderByPriorityDesc(
                        config.id, AclSubjectType.SERVICE, AclAction.PUBLISH);
        String subject = tenantId == null ? "default" : tenantId.toString();
        List<MqttTopicAcl> scoped = acls.stream()
                .filter(acl -> subject.equals(acl.subjectId) || "*".equals(acl.subjectId)
                        || "default".equals(acl.subjectId))
                .toList();
        if (scoped.isEmpty()) {
            String prefix = config.serviceTopicPrefix == null || config.serviceTopicPrefix.isBlank()
                    ? props.mqtt.serviceTopicPrefix : config.serviceTopicPrefix;
            if (topic.startsWith(prefix)) {
                return;
            }
            throw ApiException.forbidden("Topic 不在服务端授权发布范围内，必须以前缀 " + prefix + " 开头");
        }
        boolean allowed = false;
        for (MqttTopicAcl acl : scoped) {
            if (TopicRules.matches(acl.topicPattern, topic)) {
                if (acl.effect == AclEffect.DENY) {
                    throw ApiException.forbidden("Topic 被服务端 ACL 显式拒绝");
                }
                allowed = true;
            }
        }
        if (!allowed) {
            throw ApiException.forbidden("Topic 未被服务端 ACL 授权");
        }
    }

    private void validatePayload(byte[] payload) {
        if (payload == null) {
            throw ApiException.validation("payload", "消息内容不能为空");
        }
        if (payload.length == 0) {
            throw ApiException.validation("payload", "消息内容不能为空");
        }
        if (payload.length > props.mqtt.maxPayloadBytes) {
            throw ApiException.payloadTooLarge("消息内容超过最大允许大小 " + props.mqtt.maxPayloadBytes + " 字节");
        }
    }

    private static String normalizeMessageId(String messageId) {
        String value = messageId == null ? "" : messageId.trim();
        if (value.isEmpty()) {
            return UUID.randomUUID().toString();
        }
        if (value.length() > 128) {
            throw ApiException.validation("message_id", "messageId 长度不能超过 128");
        }
        return value;
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }

    public record PublishOutcome(boolean success, String code, String message,
                                 MqttPublishRecord record, String deviceId) {
        public Map<String, Object> toMap() {
            return Map.of(
                    "deviceId", deviceId == null ? "" : deviceId,
                    "success", success,
                    "code", code,
                    "message", message == null ? "" : message,
                    "recordId", record == null ? "" : record.id.toString(),
                    "topic", record == null ? "" : record.topic,
                    "messageId", record == null ? "" : record.messageId);
        }
    }

    public record BatchOutcome(int total, int successCount, int failureCount, List<PublishOutcome> results) {
    }
}
