package com.platform.im.application;

import com.platform.im.config.AppProperties;
import com.platform.im.domain.mqtt.AclAction;
import com.platform.im.domain.mqtt.AclEffect;
import com.platform.im.domain.mqtt.AclSubjectType;
import com.platform.im.domain.mqtt.CredentialStatus;
import com.platform.im.domain.mqtt.MqttAccessConfig;
import com.platform.im.domain.mqtt.MqttBroker;
import com.platform.im.domain.mqtt.MqttDeviceCredential;
import com.platform.im.domain.mqtt.MqttTopicAcl;
import com.platform.im.domain.mqtt.TopicRules;
import com.platform.im.domain.repository.MqttAccessConfigRepository;
import com.platform.im.domain.repository.MqttBrokerRepository;
import com.platform.im.domain.repository.MqttDeviceCredentialRepository;
import com.platform.im.domain.repository.MqttTopicAclRepository;
import com.platform.im.security.AuthPrincipal;
import com.platform.im.security.DeviceAuthenticator;
import com.platform.im.shared.ApiException;
import com.platform.im.shared.CryptoService;
import com.platform.im.shared.Ids;
import com.platform.im.shared.PageQuery;
import com.platform.im.shared.PageResult;
import com.platform.im.web.dto.MqttDtos;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class MqttDeviceCredentialService implements DeviceAuthenticator {
    private final MqttDeviceCredentialRepository repository;
    private final MqttAccessConfigRepository accessConfigRepository;
    private final MqttBrokerRepository brokerRepository;
    private final MqttTopicAclRepository aclRepository;
    private final MqttAccessConfigService accessConfigService;
    private final CryptoService crypto;
    private final AppProperties props;

    public MqttDeviceCredentialService(MqttDeviceCredentialRepository repository,
                                       MqttAccessConfigRepository accessConfigRepository,
                                       MqttBrokerRepository brokerRepository,
                                       MqttTopicAclRepository aclRepository,
                                       MqttAccessConfigService accessConfigService,
                                       CryptoService crypto,
                                       AppProperties props) {
        this.repository = repository;
        this.accessConfigRepository = accessConfigRepository;
        this.brokerRepository = brokerRepository;
        this.aclRepository = aclRepository;
        this.accessConfigService = accessConfigService;
        this.crypto = crypto;
        this.props = props;
    }

    public PageResult<MqttDtos.CredentialView> list(Integer page, Integer size, String tenantId, String deviceId) {
        PageQuery query = PageQuery.of(page, size);
        Sort sort = Sort.by(Sort.Direction.DESC, "createdAt");
        UUID tenant = Ids.parseUuid(tenantId, "tenant_id");
        Page<MqttDeviceCredential> result;
        if (tenant != null && deviceId != null && !deviceId.isBlank()) {
            result = repository.findByTenantIdAndDeviceIdContainingIgnoreCaseAndDeletedFalse(
                    tenant, deviceId.trim(), query.pageable(sort));
        } else if (tenant != null) {
            result = repository.findByTenantIdAndDeletedFalse(tenant, query.pageable(sort));
        } else if (deviceId != null && !deviceId.isBlank()) {
            result = repository.findByDeviceIdContainingIgnoreCaseAndDeletedFalse(deviceId.trim(), query.pageable(sort));
        } else {
            result = repository.findByDeletedFalse(query.pageable(sort));
        }
        return PageResult.of(result, this::toView);
    }

    public MqttDtos.CredentialView get(UUID id) {
        return toView(require(id));
    }

    @Transactional
    public MqttDtos.CredentialCreatedView create(MqttDtos.CredentialCreateRequest request) {
        TopicRules.validateDeviceId(request.deviceId());
        UUID tenant = Ids.parseUuid(request.tenantId(), "tenant_id");
        MqttAccessConfig config = request.accessConfigId() == null
                ? accessConfigService.resolveDefault(tenant)
                : accessConfigService.requireActive(request.accessConfigId());
        if (tenant == null) {
            tenant = config.tenantId;
        }
        UUID finalTenant = tenant;
        var existing = tenant == null
                ? repository.findFirstByTenantIdIsNullAndDeviceIdAndDeletedFalse(request.deviceId())
                : repository.findByTenantIdAndDeviceIdAndDeletedFalse(tenant, request.deviceId());
        if (existing.isPresent()) {
            throw ApiException.conflict("该设备已存在 MQTT 凭证，请使用轮换接口");
        }
        MqttBroker broker = requireBroker(config.brokerId);

        String plainPassword = CryptoService.randomSecret(32);
        MqttDeviceCredential credential = new MqttDeviceCredential();
        credential.tenantId = finalTenant;
        credential.deviceId = request.deviceId().trim();
        credential.accessConfigId = config.id;
        credential.brokerId = config.brokerId;
        credential.username = generateUsername();
        credential.passwordHash = crypto.deviceSecretHash(plainPassword);
        credential.passwordCipher = crypto.encrypt(plainPassword);
        credential.status = CredentialStatus.ACTIVE;
        credential.configVersion = 1;
        credential.expiresAt = request.expiresAt();
        MqttDeviceCredential saved = repository.save(credential);

        if (request.createDefaultAcls() == null || request.createDefaultAcls()) {
            List<MqttTopicAcl> acls = accessConfigService.defaultAcls(config, saved.deviceId);
            aclRepository.saveAll(acls);
        }
        return new MqttDtos.CredentialCreatedView(toView(saved), plainPassword);
    }

    @Transactional
    public MqttDtos.CredentialCreatedView rotate(UUID id) {
        MqttDeviceCredential credential = require(id);
        if (credential.status == CredentialStatus.REVOKED) {
            throw ApiException.conflict("已撤销的凭证不能轮换");
        }
        if (credential.deleted) {
            throw ApiException.notFound("设备凭证不存在");
        }
        MqttAccessConfig config = accessConfigService.requireActive(credential.accessConfigId);
        requireBroker(config.brokerId);
        String plainPassword = CryptoService.randomSecret(32);
        credential.passwordHash = crypto.deviceSecretHash(plainPassword);
        credential.passwordCipher = crypto.encrypt(plainPassword);
        credential.status = CredentialStatus.ACTIVE;
        credential.configVersion = credential.configVersion + 1;
        credential.rotatedAt = Instant.now();
        credential.disabledReason = null;
        return new MqttDtos.CredentialCreatedView(toView(repository.save(credential)), plainPassword);
    }

    @Transactional
    public MqttDtos.CredentialView disable(UUID id, String reason) {
        MqttDeviceCredential credential = require(id);
        if (credential.status == CredentialStatus.REVOKED) {
            throw ApiException.conflict("已撤销的凭证不能禁用");
        }
        credential.status = CredentialStatus.DISABLED;
        credential.disabledReason = reason;
        credential.configVersion = credential.configVersion + 1;
        return toView(repository.save(credential));
    }

    @Transactional
    public MqttDtos.CredentialView revoke(UUID id, String reason) {
        MqttDeviceCredential credential = require(id);
        credential.status = CredentialStatus.REVOKED;
        credential.disabledReason = reason;
        credential.configVersion = credential.configVersion + 1;
        credential.passwordHash = CryptoService.sha256Hex("revoked:" + UUID.randomUUID());
        credential.passwordCipher = crypto.encrypt(CryptoService.randomSecret(32));
        return toView(repository.save(credential));
    }

    public int currentVersion(String tenantId, String deviceId) {
        UUID tenant = Ids.parseUuid(tenantId, "tenant_id");
        MqttDeviceCredential credential = findIdentity(deviceId, tenant)
                .orElseThrow(() -> ApiException.notFound("设备 MQTT 凭证不存在"));
        return credential.configVersion;
    }

    @Transactional
    public MqttDtos.DeviceConfigView deviceConfig(UUID tenantId, String deviceId) {
        MqttDeviceCredential credential = findIdentity(deviceId, tenantId)
                .orElseThrow(() -> ApiException.unauthorized("设备 MQTT 凭证不存在"));
        Context context = requireUsable(credential);
        String password = crypto.decrypt(credential.passwordCipher);
        Map<String, String> variables = variables(credential);
        String publishTopic = TopicRules.resolve(context.config.publishTopicTemplate, variables);
        String subscribeTopic = TopicRules.resolve(context.config.subscribeTopicTemplate, variables);
        List<MqttDtos.TopicPermissionView> permissions = permissions(context.config.id, deviceId, credential, variables);
        boolean tls = context.config.tlsEnabled;
        if (tls && !context.broker.tlsEnabled) {
            throw ApiException.unavailable("接入配置要求 TLS，但 Broker 未启用 TLS");
        }
        int port = tls
                ? (context.broker.tlsPort == null ? 8883 : context.broker.tlsPort)
                : context.broker.tcpPort;
        String brokerUrl = (tls ? "ssl://" : "tcp://") + context.broker.host;
        return new MqttDtos.DeviceConfigView(credential.tenantId, credential.deviceId, brokerUrl, port,
                "5.0", tls, credential.username, credential.username, password,
                context.config.keepAliveSeconds, context.config.cleanStart, context.config.sessionExpirySeconds,
                context.config.defaultQos, publishTopic, subscribeTopic, permissions,
                credential.configVersion, context.config.configVersion, credential.expiresAt);
    }

    @Override
    @Transactional
    public AuthPrincipal authenticate(String deviceId, String token, UUID tenantId) {
        MqttDeviceCredential credential = findIdentity(deviceId, tenantId)
                .orElseThrow(() -> ApiException.unauthorized("设备 MQTT 凭证不存在"));
        if (!crypto.verifyDeviceSecret(token, credential.passwordHash)) {
            throw ApiException.unauthorized("设备凭证无效");
        }
        Context context = requireUsable(credential);
        touchLastAuth(credential);
        return AuthPrincipal.device(credential.deviceId, context.config.tenantId != null
                ? context.config.tenantId : credential.tenantId);
    }

    @Override
    @Transactional
    public AuthPrincipal resolve(String deviceId, UUID tenantId) {
        MqttDeviceCredential credential = findIdentity(deviceId, tenantId)
                .orElseThrow(() -> ApiException.unauthorized("设备 MQTT 凭证不存在"));
        requireUsable(credential);
        touchLastAuth(credential);
        return AuthPrincipal.device(credential.deviceId, credential.tenantId);
    }

    @Transactional
    public boolean authenticateMqttUser(String username, String password) {
        MqttDeviceCredential credential = repository.findByUsernameAndDeletedFalse(username)
                .orElse(null);
        if (credential == null || !crypto.verifyDeviceSecret(password, credential.passwordHash)) {
            return false;
        }
        requireUsable(credential);
        touchLastAuth(credential);
        return true;
    }

    public boolean authorizeTopic(String username, String topic, String actionText) {
        MqttDeviceCredential credential = repository.findByUsernameAndDeletedFalse(username)
                .orElse(null);
        if (credential == null) {
            return false;
        }
        AclAction action;
        try {
            action = AclAction.valueOf(actionText.trim().toUpperCase(java.util.Locale.ROOT));
        } catch (Exception e) {
            return false;
        }
        Context context;
        try {
            context = requireUsable(credential);
            if (action == AclAction.PUBLISH) {
                TopicRules.validatePublishTopic(topic);
            } else {
                TopicRules.validateTopicPattern(topic);
            }
        } catch (RuntimeException ex) {
            return false;
        }
        List<MqttTopicAcl> acls = aclRepository
                .findByAccessConfigIdAndSubjectTypeAndSubjectIdAndActionAndEnabledTrueOrderByPriorityDesc(
                        context.config.id, AclSubjectType.DEVICE, credential.deviceId, action);
        if (action == AclAction.SUBSCRIBE) {
            return decideSubscribe(acls, topic);
        }
        return decide(acls, topic, action);
    }

    public MqttDeviceCredential requireForPublish(UUID tenantId, String deviceId) {
        TopicRules.validateDeviceId(deviceId);
        MqttDeviceCredential credential = findIdentity(deviceId, tenantId)
                .orElseThrow(() -> ApiException.notFound("设备 MQTT 凭证不存在"));
        if (!credential.isUsable()) {
            throw ApiException.badRequest("设备 MQTT 凭证不可用");
        }
        requireUsable(credential);
        return credential;
    }

    /**
     * 校验平台服务是否可以向该设备配置推导出的 Topic 发布消息。
     * 若设备未配置任何 PUBLISH ACL，则仅允许接入配置模板解析出的发布 Topic。
     */
    public boolean authorizePublish(MqttDeviceCredential credential, String topic) {
        Context context = requireUsable(credential);
        List<MqttTopicAcl> acls = aclRepository
                .findByAccessConfigIdAndSubjectTypeAndSubjectIdAndActionAndEnabledTrueOrderByPriorityDesc(
                        context.config.id, AclSubjectType.DEVICE, credential.deviceId, AclAction.PUBLISH);
        if (acls.isEmpty()) {
            String expected = TopicRules.resolve(context.config.publishTopicTemplate, variables(credential));
            return expected.equals(topic);
        }
        return decide(acls, topic, AclAction.PUBLISH);
    }

    public Context contextFor(MqttDeviceCredential credential) {
        return requireUsable(credential);
    }

    public MqttDeviceCredential require(UUID id) {
        return repository.findByIdAndDeletedFalse(id)
                .orElseThrow(() -> ApiException.notFound("设备 MQTT 凭证不存在"));
    }

    public MqttDtos.CredentialView toView(MqttDeviceCredential credential) {
        return new MqttDtos.CredentialView(credential.id, credential.tenantId, credential.deviceId,
                credential.accessConfigId, credential.brokerId, credential.username, credential.status,
                credential.configVersion, credential.expiresAt, credential.lastAuthAt, credential.rotatedAt,
                credential.disabledReason, credential.createdAt, credential.updatedAt);
    }

    public Map<String, String> variables(MqttDeviceCredential credential) {
        Map<String, String> variables = new LinkedHashMap<>();
        variables.put("deviceId", credential.deviceId);
        variables.put("tenantId", credential.tenantId == null ? "" : credential.tenantId.toString());
        variables.put("clientId", credential.username);
        variables.put("username", credential.username);
        return variables;
    }

    private java.util.Optional<MqttDeviceCredential> findIdentity(String deviceId, UUID tenantId) {
        if (deviceId == null || deviceId.isBlank()) {
            return java.util.Optional.empty();
        }
        if (tenantId != null) {
            return repository.findByTenantIdAndDeviceIdAndDeletedFalse(tenantId, deviceId);
        }
        return repository.findFirstByTenantIdIsNullAndDeviceIdAndDeletedFalse(deviceId);
    }

    private Context requireUsable(MqttDeviceCredential credential) {
        if (credential.deleted || credential.status == CredentialStatus.REVOKED) {
            throw ApiException.unauthorized("设备凭证已撤销");
        }
        if (credential.status == CredentialStatus.DISABLED) {
            throw ApiException.unauthorized("设备凭证已禁用");
        }
        if (credential.expiresAt != null && !credential.expiresAt.isAfter(Instant.now())) {
            throw ApiException.unauthorized("设备凭证已过期");
        }
        MqttAccessConfig config = accessConfigRepository.findByIdAndDeletedFalse(credential.accessConfigId)
                .orElseThrow(() -> ApiException.unauthorized("MQTT 接入配置不存在"));
        if (!config.enabled) {
            throw ApiException.unauthorized("MQTT 接入配置已禁用");
        }
        MqttBroker broker = brokerRepository.findById(config.brokerId)
                .orElseThrow(() -> ApiException.unauthorized("MQTT Broker 不存在"));
        if (!broker.enabled) {
            throw ApiException.unauthorized("MQTT Broker 已禁用");
        }
        return new Context(config, broker);
    }

    private MqttBroker requireBroker(UUID brokerId) {
        MqttBroker broker = brokerRepository.findById(brokerId)
                .orElseThrow(() -> ApiException.notFound("MQTT Broker 不存在"));
        if (!broker.enabled) {
            throw ApiException.badRequest("MQTT Broker 已禁用");
        }
        return broker;
    }

    private void touchLastAuth(MqttDeviceCredential credential) {
        if (credential.lastAuthAt == null
                || credential.lastAuthAt.isBefore(Instant.now().minus(Duration.ofSeconds(60)))) {
            credential.lastAuthAt = Instant.now();
            repository.save(credential);
        }
    }

    private String generateUsername() {
        for (int i = 0; i < 10; i++) {
            String candidate = "dev_" + CryptoService.randomSecret(18).replace("-", "").replace("_", "");
            if (repository.findByUsernameAndDeletedFalse(candidate).isEmpty()) {
                return candidate;
            }
        }
        throw ApiException.internal("无法生成唯一的 MQTT 用户名");
    }

    private List<MqttDtos.TopicPermissionView> permissions(UUID accessConfigId, String deviceId,
                                                           MqttDeviceCredential credential,
                                                           Map<String, String> variables) {
        List<MqttDtos.TopicPermissionView> out = new ArrayList<>();
        for (AclAction action : List.of(AclAction.PUBLISH, AclAction.SUBSCRIBE)) {
            List<MqttTopicAcl> acls = aclRepository
                    .findByAccessConfigIdAndSubjectTypeAndSubjectIdAndActionAndEnabledTrueOrderByPriorityDesc(
                            accessConfigId, AclSubjectType.DEVICE, deviceId, action);
            for (MqttTopicAcl acl : acls) {
                String topic;
                try {
                    topic = TopicRules.resolve(acl.topicPattern, variables);
                } catch (RuntimeException e) {
                    topic = acl.topicPattern;
                }
                out.add(new MqttDtos.TopicPermissionView(topic, acl.action.name(), acl.effect.name(), acl.qosMax));
            }
        }
        return out;
    }

    private boolean decide(List<MqttTopicAcl> acls, String topic, AclAction action) {
        boolean allowed = false;
        for (MqttTopicAcl acl : acls) {
            if (acl.action != action || !acl.enabled) {
                continue;
            }
            if (TopicRules.matches(acl.topicPattern, topic)) {
                if (acl.effect == AclEffect.DENY) {
                    return false;
                }
                allowed = true;
            }
        }
        return allowed;
    }

    private boolean decideSubscribe(List<MqttTopicAcl> acls, String filter) {
        boolean allowed = false;
        for (MqttTopicAcl acl : acls) {
            if (acl.action != AclAction.SUBSCRIBE || !acl.enabled) {
                continue;
            }
            if (TopicRules.covers(acl.topicPattern, filter)) {
                if (acl.effect == AclEffect.DENY) {
                    return false;
                }
                allowed = true;
            }
        }
        return allowed;
    }

    public record Context(MqttAccessConfig config, MqttBroker broker) {
    }
}
