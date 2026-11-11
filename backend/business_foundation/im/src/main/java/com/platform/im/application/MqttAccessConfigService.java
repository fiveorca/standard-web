package com.platform.im.application;

import com.platform.im.domain.mqtt.AclAction;
import com.platform.im.domain.mqtt.AclEffect;
import com.platform.im.domain.mqtt.AclSubjectType;
import com.platform.im.domain.mqtt.DeviceAuthMode;
import com.platform.im.domain.mqtt.MqttAccessConfig;
import com.platform.im.domain.mqtt.MqttBroker;
import com.platform.im.domain.mqtt.MqttTopicAcl;
import com.platform.im.domain.mqtt.TopicRules;
import com.platform.im.domain.repository.MqttAccessConfigRepository;
import com.platform.im.domain.repository.MqttBrokerRepository;
import com.platform.im.domain.repository.MqttDeviceCredentialRepository;
import com.platform.im.domain.repository.MqttTopicAclRepository;
import com.platform.im.shared.ApiException;
import com.platform.im.shared.Ids;
import com.platform.im.shared.PageQuery;
import com.platform.im.shared.PageResult;
import com.platform.im.web.dto.MqttDtos;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
public class MqttAccessConfigService {
    private final MqttAccessConfigRepository repository;
    private final MqttBrokerRepository brokerRepository;
    private final MqttDeviceCredentialRepository credentialRepository;
    private final MqttTopicAclRepository aclRepository;

    public MqttAccessConfigService(MqttAccessConfigRepository repository,
                                   MqttBrokerRepository brokerRepository,
                                   MqttDeviceCredentialRepository credentialRepository,
                                   MqttTopicAclRepository aclRepository) {
        this.repository = repository;
        this.brokerRepository = brokerRepository;
        this.credentialRepository = credentialRepository;
        this.aclRepository = aclRepository;
    }

    public PageResult<MqttDtos.AccessConfigView> list(Integer page, Integer size, String q, String tenantId) {
        PageQuery query = PageQuery.of(page, size);
        Sort sort = Sort.by(Sort.Direction.DESC, "createdAt");
        UUID tenant = Ids.parseUuid(tenantId, "tenant_id");
        Page<MqttAccessConfig> result;
        if (q != null && !q.isBlank()) {
            result = repository.findByCodeContainingIgnoreCaseAndDeletedFalse(q.trim(), query.pageable(sort));
        } else if (tenant != null) {
            result = repository.findByTenantIdAndDeletedFalse(tenant, query.pageable(sort));
        } else {
            result = repository.findByDeletedFalse(query.pageable(sort));
        }
        return PageResult.of(result, this::toView);
    }

    public MqttDtos.AccessConfigView get(UUID id) {
        return toView(require(id));
    }

    @Transactional
    public MqttDtos.AccessConfigView create(MqttDtos.AccessConfigRequest request) {
        String code = request.code() == null ? "" : request.code().trim();
        if (code.isBlank()) {
            throw ApiException.validation("code", "接入配置 code 不能为空");
        }
        if (repository.existsByCodeIgnoreCaseAndDeletedFalse(code)) {
            throw ApiException.conflict("接入配置 code 已存在");
        }
        MqttBroker broker = requireEnabledBroker(request.brokerId());
        MqttAccessConfig config = new MqttAccessConfig();
        config.code = code;
        config.name = request.name().trim();
        config.tenantId = Ids.parseUuid(request.tenantId(), "tenant_id");
        config.brokerId = broker.id;
        config.enabled = request.enabled() == null || request.enabled();
        config.protocolVersion = "5.0";
        config.defaultQos = request.defaultQos() == null ? 1 : request.defaultQos();
        config.keepAliveSeconds = request.keepAliveSeconds() == null ? 60 : request.keepAliveSeconds();
        config.cleanStart = request.cleanStart() == null || request.cleanStart();
        config.sessionExpirySeconds = request.sessionExpirySeconds() == null ? 0 : request.sessionExpirySeconds();
        config.messageExpiryIntervalSeconds = request.messageExpiryIntervalSeconds() == null
                ? 0 : request.messageExpiryIntervalSeconds();
        config.retainDefault = Boolean.TRUE.equals(request.retainDefault());
        config.publishTopicTemplate = template(request.publishTopicTemplate(), "devices/{deviceId}/up", true);
        config.subscribeTopicTemplate = template(request.subscribeTopicTemplate(), "devices/{deviceId}/down", false);
        config.serviceTopicPrefix = request.serviceTopicPrefix() == null || request.serviceTopicPrefix().isBlank()
                ? "tenants/" : request.serviceTopicPrefix().trim();
        config.tlsEnabled = Boolean.TRUE.equals(request.tlsEnabled());
        config.authMode = request.authMode() == null ? DeviceAuthMode.CREDENTIAL : request.authMode();
        config.metadataJson = request.metadataJson() == null ? "{}" : request.metadataJson();
        config.configVersion = 1;
        if (Boolean.TRUE.equals(request.defaultConfig())) {
            clearDefault(config.tenantId);
            config.defaultConfig = true;
        }
        return toView(repository.save(config));
    }

    @Transactional
    public MqttDtos.AccessConfigView update(UUID id, MqttDtos.AccessConfigRequest request) {
        MqttAccessConfig config = require(id);
        String code = request.code() == null || request.code().isBlank() ? config.code : request.code().trim();
        repository.findByCodeIgnoreCaseAndDeletedFalse(code).ifPresent(existing -> {
            if (!existing.id.equals(id)) {
                throw ApiException.conflict("接入配置 code 已存在");
            }
        });
        MqttBroker broker = requireEnabledBroker(request.brokerId());
        config.code = code;
        config.name = request.name().trim();
        UUID newTenant = Ids.parseUuid(request.tenantId(), "tenant_id");
        if (config.defaultConfig && !java.util.Objects.equals(config.tenantId, newTenant)) {
            config.defaultConfig = false;
        }
        config.tenantId = newTenant;
        config.brokerId = broker.id;
        if (request.enabled() != null) {
            config.enabled = request.enabled();
        }
        if (request.defaultQos() != null) {
            config.defaultQos = request.defaultQos();
        }
        if (request.keepAliveSeconds() != null) {
            config.keepAliveSeconds = request.keepAliveSeconds();
        }
        if (request.cleanStart() != null) {
            config.cleanStart = request.cleanStart();
        }
        if (request.sessionExpirySeconds() != null) {
            config.sessionExpirySeconds = request.sessionExpirySeconds();
        }
        if (request.messageExpiryIntervalSeconds() != null) {
            config.messageExpiryIntervalSeconds = request.messageExpiryIntervalSeconds();
        }
        if (request.retainDefault() != null) {
            config.retainDefault = request.retainDefault();
        }
        if (request.publishTopicTemplate() != null) {
            config.publishTopicTemplate = template(request.publishTopicTemplate(), null, true);
        }
        if (request.subscribeTopicTemplate() != null) {
            config.subscribeTopicTemplate = template(request.subscribeTopicTemplate(), null, false);
        }
        if (request.serviceTopicPrefix() != null) {
            config.serviceTopicPrefix = request.serviceTopicPrefix().trim();
        }
        if (request.tlsEnabled() != null) {
            config.tlsEnabled = request.tlsEnabled();
        }
        if (request.authMode() != null) {
            config.authMode = request.authMode();
        }
        if (request.metadataJson() != null) {
            config.metadataJson = request.metadataJson();
        }
        if (Boolean.TRUE.equals(request.defaultConfig()) && !config.defaultConfig) {
            clearDefault(config.tenantId);
            config.defaultConfig = true;
        }
        config.configVersion = config.configVersion + 1;
        return toView(repository.save(config));
    }

    @Transactional
    public void delete(UUID id) {
        MqttAccessConfig config = require(id);
        if (credentialRepository.countByAccessConfigIdAndDeletedFalse(id) > 0) {
            throw ApiException.conflict("接入配置仍被设备凭证引用，无法删除");
        }
        config.deleted = true;
        config.defaultConfig = false;
        repository.save(config);
    }

    @Transactional
    public MqttDtos.AccessConfigView setEnabled(UUID id, boolean enabled) {
        MqttAccessConfig config = require(id);
        config.enabled = enabled;
        if (!enabled) {
            config.defaultConfig = false;
        }
        config.configVersion = config.configVersion + 1;
        return toView(repository.save(config));
    }

    @Transactional
    public MqttDtos.AccessConfigView setDefault(UUID id) {
        MqttAccessConfig config = require(id);
        if (!config.enabled) {
            throw ApiException.badRequest("禁用的接入配置不能设为默认");
        }
        clearDefault(config.tenantId);
        config.defaultConfig = true;
        return toView(repository.save(config));
    }

    public List<MqttDtos.TopicAclView> listAcls(UUID accessConfigId) {
        require(accessConfigId);
        return aclRepository.findByAccessConfigIdOrderByPriorityDesc(accessConfigId).stream()
                .map(this::toAclView).toList();
    }

    @Transactional
    public MqttDtos.TopicAclView addAcl(UUID accessConfigId, MqttDtos.TopicAclRequest request) {
        MqttAccessConfig config = require(accessConfigId);
        TopicRules.validateTopicPattern(request.topicPattern());
        MqttTopicAcl acl = new MqttTopicAcl();
        acl.tenantId = config.tenantId;
        acl.accessConfigId = config.id;
        acl.subjectType = request.subjectType();
        acl.subjectId = request.subjectId().trim();
        acl.topicPattern = request.topicPattern().trim();
        acl.action = request.action();
        acl.effect = request.effect() == null ? AclEffect.ALLOW : request.effect();
        acl.qosMax = request.qosMax() == null ? 2 : request.qosMax();
        acl.priority = request.priority() == null ? 0 : request.priority();
        acl.enabled = request.enabled() == null || request.enabled();
        MqttTopicAcl saved = aclRepository.save(acl);
        bumpVersion(config);
        return toAclView(saved);
    }

    @Transactional
    public void deleteAcl(UUID accessConfigId, UUID aclId) {
        MqttAccessConfig config = require(accessConfigId);
        MqttTopicAcl acl = aclRepository.findById(aclId)
                .orElseThrow(() -> ApiException.notFound("Topic 权限不存在"));
        if (!config.id.equals(acl.accessConfigId)) {
            throw ApiException.notFound("Topic 权限不属于该接入配置");
        }
        aclRepository.delete(acl);
        bumpVersion(config);
    }

    public MqttAccessConfig require(UUID id) {
        return repository.findByIdAndDeletedFalse(id)
                .orElseThrow(() -> ApiException.notFound("MQTT 接入配置不存在"));
    }

    public MqttAccessConfig requireActive(UUID id) {
        MqttAccessConfig config = require(id);
        if (!config.enabled) {
            throw ApiException.badRequest("MQTT 接入配置已禁用");
        }
        return config;
    }

    public MqttAccessConfig resolveDefault(UUID tenantId) {
        if (tenantId != null) {
            var tenantDefault = repository.findFirstByTenantIdAndDefaultConfigTrueAndDeletedFalse(tenantId);
            if (tenantDefault.isPresent() && tenantDefault.get().enabled) {
                return tenantDefault.get();
            }
        }
        return repository.findFirstByDefaultConfigTrueAndDeletedFalseAndTenantIdIsNull()
                .filter(config -> config.enabled)
                .orElseGet(() -> repository.findByDeletedFalseOrderByNameAsc().stream()
                        .filter(config -> config.enabled)
                        .findFirst()
                        .orElseThrow(() -> ApiException.unavailable("没有可用的 MQTT 接入配置")));
    }

    public MqttDtos.AccessConfigView toView(MqttAccessConfig config) {
        String brokerCode = brokerRepository.findById(config.brokerId)
                .map(broker -> broker.code).orElse(null);
        return new MqttDtos.AccessConfigView(config.id, config.code, config.name, config.tenantId,
                config.brokerId, brokerCode, config.enabled, config.defaultConfig, config.protocolVersion,
                config.defaultQos, config.keepAliveSeconds, config.cleanStart, config.sessionExpirySeconds,
                config.messageExpiryIntervalSeconds, config.retainDefault, config.publishTopicTemplate,
                config.subscribeTopicTemplate, config.serviceTopicPrefix, config.tlsEnabled,
                config.authMode.name(), config.configVersion, config.metadataJson,
                config.createdAt, config.updatedAt);
    }

    public MqttDtos.TopicAclView toAclView(MqttTopicAcl acl) {
        return new MqttDtos.TopicAclView(acl.id, acl.accessConfigId, acl.subjectType.name(), acl.subjectId,
                acl.topicPattern, acl.action.name(), acl.effect.name(), acl.qosMax, acl.priority,
                acl.enabled, acl.createdAt);
    }

    private MqttBroker requireEnabledBroker(UUID brokerId) {
        if (brokerId == null) {
            throw ApiException.validation("broker_id", "brokerId 不能为空");
        }
        MqttBroker broker = brokerRepository.findById(brokerId)
                .orElseThrow(() -> ApiException.notFound("MQTT Broker 不存在"));
        if (!broker.enabled) {
            throw ApiException.badRequest("MQTT Broker 已禁用");
        }
        return broker;
    }

    private void clearDefault(UUID tenantId) {
        if (tenantId == null) {
            repository.findFirstByDefaultConfigTrueAndDeletedFalseAndTenantIdIsNull()
                    .ifPresent(existing -> {
                        existing.defaultConfig = false;
                        repository.save(existing);
                    });
        } else {
            repository.findFirstByTenantIdAndDefaultConfigTrueAndDeletedFalse(tenantId)
                    .ifPresent(existing -> {
                        existing.defaultConfig = false;
                        repository.save(existing);
                    });
        }
    }

    private void bumpVersion(MqttAccessConfig config) {
        config.configVersion = config.configVersion + 1;
        repository.save(config);
    }

    private static String template(String provided, String fallback, boolean publish) {
        String value = provided == null || provided.isBlank() ? fallback : provided.trim();
        if (value == null) {
            throw ApiException.validation("publish_topic_template", "Topic 模板不能为空");
        }
        if (publish) {
            TopicRules.validatePublishTopic(value.replaceAll("\\{[a-zA-Z0-9_]+}", "x"));
        } else {
            TopicRules.validateTopicPattern(value.replaceAll("\\{[a-zA-Z0-9_]+}", "x"));
        }
        return value;
    }

    /**
     * 供设备凭证创建时生成默认 ACL。
     */
    public List<MqttTopicAcl> defaultAcls(MqttAccessConfig config, String deviceId) {
        MqttTopicAcl publish = new MqttTopicAcl();
        publish.tenantId = config.tenantId;
        publish.accessConfigId = config.id;
        publish.subjectType = AclSubjectType.DEVICE;
        publish.subjectId = deviceId;
        publish.topicPattern = config.publishTopicTemplate.replace("{deviceId}", deviceId)
                .replace("{tenantId}", config.tenantId == null ? "" : config.tenantId.toString());
        publish.action = AclAction.PUBLISH;
        publish.effect = AclEffect.ALLOW;
        publish.qosMax = 2;
        publish.priority = 10;
        publish.enabled = true;

        MqttTopicAcl subscribe = new MqttTopicAcl();
        subscribe.tenantId = config.tenantId;
        subscribe.accessConfigId = config.id;
        subscribe.subjectType = AclSubjectType.DEVICE;
        subscribe.subjectId = deviceId;
        subscribe.topicPattern = config.subscribeTopicTemplate.replace("{deviceId}", deviceId)
                .replace("{tenantId}", config.tenantId == null ? "" : config.tenantId.toString());
        subscribe.action = AclAction.SUBSCRIBE;
        subscribe.effect = AclEffect.ALLOW;
        subscribe.qosMax = 2;
        subscribe.priority = 10;
        subscribe.enabled = true;
        return List.of(publish, subscribe);
    }
}
