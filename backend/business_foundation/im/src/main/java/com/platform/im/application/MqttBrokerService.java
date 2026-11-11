package com.platform.im.application;

import com.platform.im.config.AppProperties;
import com.platform.im.domain.mqtt.BrokerConnectionStatus;
import com.platform.im.domain.mqtt.BrokerType;
import com.platform.im.domain.mqtt.MqttBroker;
import com.platform.im.domain.repository.MqttAccessConfigRepository;
import com.platform.im.domain.repository.MqttBrokerRepository;
import com.platform.im.infrastructure.mqtt.MqttPublisher;
import com.platform.im.shared.ApiException;
import com.platform.im.shared.CryptoService;
import com.platform.im.shared.PageQuery;
import com.platform.im.shared.PageResult;
import com.platform.im.web.dto.MqttDtos;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
public class MqttBrokerService {
    private final MqttBrokerRepository brokerRepository;
    private final MqttAccessConfigRepository accessConfigRepository;
    private final MqttPublisher publisher;
    private final CryptoService crypto;
    private final AppProperties props;

    public MqttBrokerService(MqttBrokerRepository brokerRepository,
                             MqttAccessConfigRepository accessConfigRepository,
                             MqttPublisher publisher,
                             CryptoService crypto,
                             AppProperties props) {
        this.brokerRepository = brokerRepository;
        this.accessConfigRepository = accessConfigRepository;
        this.publisher = publisher;
        this.crypto = crypto;
        this.props = props;
    }

    public PageResult<MqttDtos.BrokerView> list(Integer page, Integer size, String q) {
        PageQuery query = PageQuery.of(page, size);
        Sort sort = Sort.by(Sort.Direction.DESC, "createdAt");
        Page<MqttBroker> result = q == null || q.isBlank()
                ? brokerRepository.findAll(query.pageable(sort))
                : brokerRepository.findByCodeContainingIgnoreCaseOrNameContainingIgnoreCase(
                q.trim(), q.trim(), query.pageable(sort));
        return PageResult.of(result, this::toView);
    }

    public MqttDtos.BrokerView get(UUID id) {
        return toView(require(id));
    }

    @Transactional
    public MqttDtos.BrokerView create(MqttDtos.BrokerRequest request) {
        String code = request.code().trim();
        if (brokerRepository.existsByCodeIgnoreCase(code)) {
            throw ApiException.conflict("Broker code 已存在");
        }
        validateProtocol(request.protocolVersion());
        MqttBroker broker = new MqttBroker();
        broker.code = code;
        broker.name = request.name().trim();
        broker.brokerType = request.brokerType() == null ? BrokerType.EMQX : request.brokerType();
        broker.host = request.host().trim();
        broker.tcpPort = request.tcpPort() == null ? 1883 : request.tcpPort();
        broker.tlsPort = request.tlsPort();
        broker.protocolVersion = "5.0";
        broker.tlsEnabled = Boolean.TRUE.equals(request.tlsEnabled());
        broker.username = blankToNull(request.username());
        broker.passwordCipher = request.password() == null || request.password().isBlank()
                ? null : crypto.encrypt(request.password());
        broker.clientIdPrefix = blankToNull(request.clientIdPrefix());
        broker.keepAliveSeconds = request.keepAliveSeconds() == null ? props.mqtt.keepAliveSeconds : request.keepAliveSeconds();
        broker.cleanStart = request.cleanStart() == null || request.cleanStart();
        broker.sessionExpirySeconds = request.sessionExpirySeconds() == null ? props.mqtt.sessionExpirySeconds : request.sessionExpirySeconds();
        broker.connectTimeoutSeconds = request.connectTimeoutSeconds() == null
                ? props.mqtt.connectTimeoutSeconds : request.connectTimeoutSeconds();
        broker.reconnectDelaySeconds = request.reconnectDelaySeconds() == null
                ? props.mqtt.reconnectDelaySeconds : request.reconnectDelaySeconds();
        broker.maxInflight = request.maxInflight() == null ? props.mqtt.maxInflight : request.maxInflight();
        broker.enabled = request.enabled() == null || request.enabled();
        broker.optionsJson = request.optionsJson() == null ? "{}" : request.optionsJson();
        if (Boolean.TRUE.equals(request.defaultBroker())) {
            clearDefault();
            broker.defaultBroker = true;
        }
        broker.status = BrokerConnectionStatus.UNKNOWN;
        return toView(brokerRepository.save(broker));
    }

    @Transactional
    public MqttDtos.BrokerView update(UUID id, MqttDtos.BrokerRequest request) {
        MqttBroker broker = require(id);
        String code = request.code().trim();
        brokerRepository.findByCodeIgnoreCase(code).ifPresent(existing -> {
            if (!existing.id.equals(id)) {
                throw ApiException.conflict("Broker code 已存在");
            }
        });
        validateProtocol(request.protocolVersion());
        broker.code = code;
        broker.name = request.name().trim();
        if (request.brokerType() != null) {
            broker.brokerType = request.brokerType();
        }
        broker.host = request.host().trim();
        if (request.tcpPort() != null) {
            broker.tcpPort = request.tcpPort();
        }
        broker.tlsPort = request.tlsPort();
        broker.tlsEnabled = Boolean.TRUE.equals(request.tlsEnabled());
        broker.username = blankToNull(request.username());
        if (request.password() != null && !request.password().isBlank()) {
            broker.passwordCipher = crypto.encrypt(request.password());
        }
        broker.clientIdPrefix = blankToNull(request.clientIdPrefix());
        if (request.keepAliveSeconds() != null) {
            broker.keepAliveSeconds = request.keepAliveSeconds();
        }
        if (request.cleanStart() != null) {
            broker.cleanStart = request.cleanStart();
        }
        if (request.sessionExpirySeconds() != null) {
            broker.sessionExpirySeconds = request.sessionExpirySeconds();
        }
        if (request.connectTimeoutSeconds() != null) {
            broker.connectTimeoutSeconds = request.connectTimeoutSeconds();
        }
        if (request.reconnectDelaySeconds() != null) {
            broker.reconnectDelaySeconds = request.reconnectDelaySeconds();
        }
        if (request.maxInflight() != null) {
            broker.maxInflight = request.maxInflight();
        }
        if (request.enabled() != null) {
            broker.enabled = request.enabled();
        }
        if (Boolean.TRUE.equals(request.defaultBroker())) {
            clearDefault();
            broker.defaultBroker = true;
        }
        if (request.optionsJson() != null) {
            broker.optionsJson = request.optionsJson();
        }
        MqttBroker saved = brokerRepository.save(broker);
        publisher.evict(id);
        return toView(saved);
    }

    @Transactional
    public void delete(UUID id) {
        MqttBroker broker = require(id);
        if (accessConfigRepository.countByBrokerIdAndDeletedFalse(id) > 0) {
            throw ApiException.conflict("Broker 正在被 MQTT 接入配置引用，无法删除");
        }
        publisher.evict(id);
        brokerRepository.delete(broker);
    }

    @Transactional
    public MqttDtos.BrokerView setEnabled(UUID id, boolean enabled) {
        MqttBroker broker = require(id);
        broker.enabled = enabled;
        if (!enabled) {
            publisher.evict(id);
            broker.status = BrokerConnectionStatus.DISCONNECTED;
        }
        return toView(brokerRepository.save(broker));
    }

    @Transactional
    public MqttDtos.BrokerView setDefault(UUID id) {
        MqttBroker broker = require(id);
        if (!broker.enabled) {
            throw ApiException.badRequest("禁用的 Broker 不能设为默认");
        }
        clearDefault();
        broker.defaultBroker = true;
        return toView(brokerRepository.save(broker));
    }

    public MqttDtos.TestConnectionResult testConnection(UUID id) {
        MqttBroker broker = require(id);
        MqttPublisher.TestResult result = publisher.testConnection(broker);
        return new MqttDtos.TestConnectionResult(result.success(), result.latencyMs(), result.message());
    }

    public MqttDtos.BrokerStatusView status(UUID id) {
        MqttBroker broker = require(id);
        return new MqttDtos.BrokerStatusView(broker.id, broker.status.name(), broker.statusMessage,
                publisher.isConnected(broker.id), broker.lastConnectedAt, broker.lastCheckedAt,
                broker.reconnectCount);
    }

    public MqttBroker require(UUID id) {
        return brokerRepository.findById(id)
                .orElseThrow(() -> ApiException.notFound("MQTT Broker 不存在"));
    }

    public MqttDtos.BrokerView toView(MqttBroker broker) {
        return new MqttDtos.BrokerView(broker.id, broker.code, broker.name, broker.brokerType.name(),
                broker.host, broker.tcpPort, broker.tlsPort, broker.protocolVersion, broker.tlsEnabled,
                broker.username, broker.clientIdPrefix, broker.keepAliveSeconds, broker.cleanStart,
                broker.sessionExpirySeconds, broker.connectTimeoutSeconds, broker.reconnectDelaySeconds,
                broker.maxInflight, broker.enabled, broker.defaultBroker, broker.status.name(),
                broker.statusMessage, broker.lastConnectedAt, broker.lastCheckedAt, broker.reconnectCount,
                broker.passwordCipher != null && !broker.passwordCipher.isBlank(), broker.optionsJson,
                broker.createdAt, broker.updatedAt);
    }

    private void clearDefault() {
        brokerRepository.findFirstByDefaultBrokerTrue().ifPresent(existing -> {
            if (existing.defaultBroker) {
                existing.defaultBroker = false;
                brokerRepository.save(existing);
            }
        });
    }

    private static void validateProtocol(String protocol) {
        if (protocol != null && !protocol.isBlank() && !"5.0".equals(protocol.trim())) {
            throw ApiException.validation("protocol_version", "本服务仅支持 MQTT 5.0");
        }
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
