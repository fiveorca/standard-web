package com.platform.im.config;

import com.platform.im.domain.mqtt.BrokerConnectionStatus;
import com.platform.im.domain.mqtt.BrokerType;
import com.platform.im.domain.mqtt.DeviceAuthMode;
import com.platform.im.domain.mqtt.MqttAccessConfig;
import com.platform.im.domain.mqtt.MqttBroker;
import com.platform.im.domain.repository.MqttAccessConfigRepository;
import com.platform.im.domain.repository.MqttBrokerRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * 首次启动初始化默认 Broker 与默认接入配置，便于本地开发与 Docker Compose 直接运行。
 */
@Component
public class SeedRunner implements ApplicationRunner {
    private static final Logger log = LoggerFactory.getLogger(SeedRunner.class);

    private final AppProperties props;
    private final MqttBrokerRepository brokerRepository;
    private final MqttAccessConfigRepository accessConfigRepository;

    public SeedRunner(AppProperties props, MqttBrokerRepository brokerRepository,
                      MqttAccessConfigRepository accessConfigRepository) {
        this.props = props;
        this.brokerRepository = brokerRepository;
        this.accessConfigRepository = accessConfigRepository;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (!props.seed.enabled) {
            return;
        }
        MqttBroker broker = brokerRepository.findByCodeIgnoreCase(props.seed.brokerCode).orElseGet(() -> {
            MqttBroker created = new MqttBroker();
            created.code = props.seed.brokerCode;
            created.name = props.seed.brokerName;
            created.brokerType = BrokerType.EMQX;
            created.host = props.seed.brokerHost;
            created.tcpPort = props.seed.brokerTcpPort;
            created.tlsPort = props.seed.brokerTlsPort;
            created.protocolVersion = "5.0";
            created.tlsEnabled = props.seed.brokerTlsEnabled;
            created.enabled = true;
            created.defaultBroker = brokerRepository.countByDefaultBrokerTrue() == 0;
            created.status = BrokerConnectionStatus.UNKNOWN;
            created.clientIdPrefix = props.mqtt.clientIdPrefix;
            created.keepAliveSeconds = props.mqtt.keepAliveSeconds;
            created.cleanStart = true;
            created.sessionExpirySeconds = props.mqtt.sessionExpirySeconds;
            created.connectTimeoutSeconds = props.mqtt.connectTimeoutSeconds;
            created.reconnectDelaySeconds = props.mqtt.reconnectDelaySeconds;
            created.maxInflight = props.mqtt.maxInflight;
            MqttBroker saved = brokerRepository.save(created);
            log.info("seeded default MQTT broker code={} host={}:{}", saved.code, saved.host, saved.tcpPort);
            return saved;
        });

        accessConfigRepository.findByCodeIgnoreCaseAndDeletedFalse(props.seed.accessConfigCode).orElseGet(() -> {
            MqttAccessConfig config = new MqttAccessConfig();
            config.code = props.seed.accessConfigCode;
            config.name = "Default Access Config";
            config.tenantId = parseTenant(props.seed.tenantId);
            config.brokerId = broker.id;
            config.enabled = true;
            config.defaultConfig = true;
            config.protocolVersion = "5.0";
            config.defaultQos = 1;
            config.keepAliveSeconds = 60;
            config.cleanStart = true;
            config.sessionExpirySeconds = 0;
            config.messageExpiryIntervalSeconds = 0;
            config.retainDefault = false;
            config.publishTopicTemplate = "devices/{deviceId}/up";
            config.subscribeTopicTemplate = "devices/{deviceId}/down";
            config.serviceTopicPrefix = props.seed.serviceTopicPrefix;
            config.tlsEnabled = props.seed.brokerTlsEnabled;
            config.authMode = DeviceAuthMode.CREDENTIAL;
            config.configVersion = 1;
            config.metadataJson = "{}";
            MqttAccessConfig saved = accessConfigRepository.save(config);
            log.info("seeded default MQTT access config code={} broker={}", saved.code, broker.code);
            return saved;
        });
    }

    private static UUID parseTenant(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(value.trim());
        } catch (IllegalArgumentException e) {
            log.warn("im.seed.tenant-id 不是合法 UUID，忽略: {}", value);
            return null;
        }
    }
}
