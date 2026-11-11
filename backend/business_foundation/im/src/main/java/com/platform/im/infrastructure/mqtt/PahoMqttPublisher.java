package com.platform.im.infrastructure.mqtt;

import com.platform.im.config.AppProperties;
import com.platform.im.domain.mqtt.BrokerConnectionStatus;
import com.platform.im.domain.mqtt.MqttBroker;
import com.platform.im.shared.CryptoService;
import jakarta.annotation.PreDestroy;
import org.eclipse.paho.mqttv5.client.IMqttToken;
import org.eclipse.paho.mqttv5.client.MqttAsyncClient;
import org.eclipse.paho.mqttv5.client.MqttConnectionOptions;
import org.eclipse.paho.mqttv5.client.persist.MemoryPersistence;
import org.eclipse.paho.mqttv5.common.MqttException;
import org.eclipse.paho.mqttv5.common.MqttMessage;
import org.eclipse.paho.mqttv5.common.packet.MqttProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 基于 Eclipse Paho MQTT v5 的发布客户端。每个 Broker 复用一条长连接，
 * 配置变更时通过 evict 关闭旧连接并按新配置重连。
 */
@Component
public class PahoMqttPublisher implements MqttPublisher {
    private static final Logger log = LoggerFactory.getLogger(PahoMqttPublisher.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final AppProperties props;
    private final CryptoService crypto;
    private final MqttBrokerStatusService statusService;
    private final MqttMetrics metrics;
    private final Map<UUID, Holder> clients = new ConcurrentHashMap<>();

    public PahoMqttPublisher(AppProperties props, CryptoService crypto,
                             MqttBrokerStatusService statusService, MqttMetrics metrics) {
        this.props = props;
        this.crypto = crypto;
        this.statusService = statusService;
        this.metrics = metrics;
    }

    @Override
    public void publish(MqttBroker broker, String topic, byte[] payload, int qos,
                        boolean retained, long messageExpiryIntervalSeconds) {
        Holder holder = clients.compute(broker.id, (id, existing) -> {
            if (existing != null && existing.matches(broker, crypto)) {
                return existing;
            }
            if (existing != null) {
                existing.close();
            }
            return new Holder(createClient(broker), fingerprint(broker, crypto));
        });

        synchronized (holder) {
            try {
                if (ensureConnected(broker, holder)) {
                    metrics.recordReconnect();
                }
                MqttMessage message = new MqttMessage(payload);
                message.setQos(qos);
                message.setRetained(retained);
                if (messageExpiryIntervalSeconds > 0) {
                    MqttProperties properties = new MqttProperties();
                    properties.setMessageExpiryInterval(messageExpiryIntervalSeconds);
                    message.setProperties(properties);
                }
                IMqttToken token = holder.client.publish(topic, message);
                token.waitForCompletion(props.mqtt.publishTimeoutSeconds * 1000L);
            } catch (MqttException e) {
                holder.failed = true;
                statusService.update(broker.id, BrokerConnectionStatus.ERROR,
                        "MQTT 发布失败: " + e.getMessage(), null, false);
                throw new MqttPublishException("MQTT_PUBLISH_FAILED",
                        "MQTT 消息发布失败: " + e.getMessage(), e);
            }
        }
    }

    @Override
    public TestResult testConnection(MqttBroker broker) {
        long start = System.nanoTime();
        MqttAsyncClient client = null;
        try {
            client = createClient(broker);
            IMqttToken token = client.connect(connectionOptions(broker));
            token.waitForCompletion(props.mqtt.connectTimeoutSeconds * 1000L);
            long latency = (System.nanoTime() - start) / 1_000_000;
            client.disconnect().waitForCompletion(3000L);
            return new TestResult(true, latency, "连接成功");
        } catch (Exception e) {
            long latency = (System.nanoTime() - start) / 1_000_000;
            return new TestResult(false, latency, "连接失败: " + e.getMessage());
        } finally {
            closeQuietly(client);
        }
    }

    @Override
    public boolean isConnected(UUID brokerId) {
        Holder holder = clients.get(brokerId);
        return holder != null && holder.client.isConnected();
    }

    @Override
    public void evict(UUID brokerId) {
        Holder holder = clients.remove(brokerId);
        if (holder != null) {
            holder.close();
        }
    }

    @Override
    public Map<UUID, Boolean> connectionStates() {
        Map<UUID, Boolean> out = new ConcurrentHashMap<>();
        clients.forEach((id, holder) -> out.put(id, holder.client.isConnected()));
        return out;
    }

    /**
     * 定期刷新已缓存连接的状态，并对默认 Broker 进行保活探测。
     */
    @Scheduled(fixedDelayString = "${im.mqtt.status-check-interval-ms:30000}", initialDelay = 15000)
    public void refreshConnections() {
        clients.forEach((id, holder) -> {
            boolean connected = holder.client.isConnected();
            statusService.update(id, connected ? BrokerConnectionStatus.CONNECTED : BrokerConnectionStatus.DISCONNECTED,
                    connected ? "连接正常" : "连接已断开", connected ? Instant.now() : null, false);
        });
    }

    private boolean ensureConnected(MqttBroker broker, Holder holder) throws MqttException {
        if (holder.client.isConnected()) {
            return false;
        }
        try {
            holder.client.connect(connectionOptions(broker)).waitForCompletion(
                    props.mqtt.connectTimeoutSeconds * 1000L);
        } catch (MqttException first) {
            holder.failed = true;
            statusService.update(broker.id, BrokerConnectionStatus.ERROR,
                    "MQTT 连接失败: " + first.getMessage(), null, true);
            throw first;
        }
        boolean reconnected = holder.failed;
        holder.failed = false;
        statusService.update(broker.id, BrokerConnectionStatus.CONNECTED, "连接正常", Instant.now(), false);
        return reconnected;
    }

    private MqttConnectionOptions connectionOptions(MqttBroker broker) throws MqttException {
        MqttConnectionOptions options = new MqttConnectionOptions();
        options.setServerURIs(new String[]{serverUri(broker)});
        options.setKeepAliveInterval(broker.keepAliveSeconds > 0 ? broker.keepAliveSeconds : props.mqtt.keepAliveSeconds);
        options.setCleanStart(broker.cleanStart);
        options.setSessionExpiryInterval(broker.sessionExpirySeconds);
        options.setConnectionTimeout(Math.max(3, broker.connectTimeoutSeconds));
        options.setAutomaticReconnect(true);
        if (broker.username != null && !broker.username.isBlank()) {
            options.setUserName(broker.username);
        }
        String password = broker.passwordCipher == null ? null : crypto.decrypt(broker.passwordCipher);
        if (password != null && !password.isBlank()) {
            options.setPassword(password.getBytes(StandardCharsets.UTF_8));
        }
        if (broker.tlsEnabled) {
            try {
                SSLContext context = SSLContext.getInstance("TLS");
                context.init(null, null, RANDOM);
                SSLSocketFactory factory = context.getSocketFactory();
                options.setSocketFactory(factory);
            } catch (Exception e) {
                throw new MqttException(MqttException.REASON_CODE_CLIENT_EXCEPTION);
            }
        }
        return options;
    }

    private MqttAsyncClient createClient(MqttBroker broker) {
        try {
            String prefix = broker.clientIdPrefix == null || broker.clientIdPrefix.isBlank()
                    ? props.mqtt.clientIdPrefix : broker.clientIdPrefix;
            String clientId = prefix + "-" + UUID.randomUUID().toString().substring(0, 8);
            MqttAsyncClient client = new MqttAsyncClient(serverUri(broker), clientId, new MemoryPersistence());
            return client;
        } catch (MqttException e) {
            throw new MqttPublishException("MQTT_CLIENT_CREATE_FAILED", "MQTT 客户端创建失败: " + e.getMessage(), e);
        }
    }

    private String serverUri(MqttBroker broker) {
        boolean tls = broker.tlsEnabled;
        int port = tls ? (broker.tlsPort == null ? 8883 : broker.tlsPort) : broker.tcpPort;
        return (tls ? "ssl://" : "tcp://") + broker.host + ":" + port;
    }

    private String fingerprint(MqttBroker broker, CryptoService crypto) {
        String pwd = broker.passwordCipher == null ? "" : CryptoService.sha256Hex(broker.passwordCipher);
        return broker.host + "|" + broker.tcpPort + "|" + broker.tlsPort + "|" + broker.tlsEnabled + "|"
                + broker.username + "|" + pwd + "|" + broker.clientIdPrefix;
    }

    private static void closeQuietly(MqttAsyncClient client) {
        if (client == null) {
            return;
        }
        try {
            if (client.isConnected()) {
                client.disconnect().waitForCompletion(2000L);
            }
        } catch (Exception ignored) {
            // ignore
        }
        try {
            client.close();
        } catch (Exception ignored) {
            // ignore
        }
    }

    @PreDestroy
    public void shutdown() {
        clients.values().forEach(Holder::close);
        clients.clear();
    }

    private static final class Holder {
        final MqttAsyncClient client;
        final String fingerprint;
        volatile boolean failed;

        Holder(MqttAsyncClient client, String fingerprint) {
            this.client = client;
            this.fingerprint = fingerprint;
        }

        boolean matches(MqttBroker broker, CryptoService crypto) {
            String pwd = broker.passwordCipher == null ? "" : CryptoService.sha256Hex(broker.passwordCipher);
            String current = broker.host + "|" + broker.tcpPort + "|" + broker.tlsPort + "|" + broker.tlsEnabled + "|"
                    + broker.username + "|" + pwd + "|" + broker.clientIdPrefix;
            return fingerprint.equals(current);
        }

        void close() {
            closeQuietly(client);
        }
    }
}
