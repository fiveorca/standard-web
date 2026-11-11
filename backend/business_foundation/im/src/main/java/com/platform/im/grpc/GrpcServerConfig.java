package com.platform.im.grpc;

import com.platform.im.config.AppProperties;
import com.platform.im.grpc.proto.email.EmailServiceGrpc;
import com.platform.im.grpc.proto.mqtt.MqttMessageServiceGrpc;
import io.grpc.Server;
import io.grpc.ServerInterceptors;
import io.grpc.health.v1.HealthCheckResponse;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.ClientAuth;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContext;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContextBuilder;
import io.grpc.protobuf.services.HealthStatusManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.File;
import java.io.IOException;

/**
 * gRPC 服务端：Netty、健康检查、可选 TLS/mTLS、认证与指标拦截器。
 */
@Configuration
@ConditionalOnProperty(prefix = "im.grpc", name = "enabled", havingValue = "true", matchIfMissing = true)
public class GrpcServerConfig {
    private static final Logger log = LoggerFactory.getLogger(GrpcServerConfig.class);

    @Bean(destroyMethod = "shutdown")
    public Server grpcServer(AppProperties props,
                             GrpcAuthInterceptor authInterceptor,
                             GrpcMetricsInterceptor metricsInterceptor,
                             MqttMessageGrpcService mqttService,
                             EmailGrpcService emailService) throws IOException {
        HealthStatusManager health = new HealthStatusManager();
        NettyServerBuilder builder = NettyServerBuilder.forPort(props.grpc.port)
                .addService(ServerInterceptors.intercept(mqttService, authInterceptor, metricsInterceptor))
                .addService(ServerInterceptors.intercept(emailService, authInterceptor, metricsInterceptor))
                .addService(health.getHealthService())
                .maxInboundMessageSize(props.grpc.maxInboundMessageSize)
                .permitKeepAliveWithoutCalls(true);
        if (props.grpc.tlsEnabled) {
            builder.sslContext(sslContext(props));
        }
        Server server = builder.build().start();
        health.setStatus("", HealthCheckResponse.ServingStatus.SERVING);
        health.setStatus(MqttMessageServiceGrpc.SERVICE_NAME, HealthCheckResponse.ServingStatus.SERVING);
        health.setStatus(EmailServiceGrpc.SERVICE_NAME, HealthCheckResponse.ServingStatus.SERVING);
        log.info("gRPC server started on port {} tls={} mtls={}", props.grpc.port,
                props.grpc.tlsEnabled, props.grpc.requireClientAuth);
        return server;
    }

    private SslContext sslContext(AppProperties props) throws IOException {
        requirePath(props.grpc.certificateChainPath, "im.grpc.certificate-chain-path");
        requirePath(props.grpc.privateKeyPath, "im.grpc.private-key-path");
        SslContextBuilder ssl = GrpcSslContexts.forServer(
                new File(props.grpc.certificateChainPath), new File(props.grpc.privateKeyPath));
        if (props.grpc.requireClientAuth) {
            requirePath(props.grpc.trustCertificatePath, "im.grpc.trust-certificate-path");
            ssl.trustManager(new File(props.grpc.trustCertificatePath));
            ssl.clientAuth(ClientAuth.REQUIRE);
        }
        return ssl.build();
    }

    private static void requirePath(String path, String property) {
        if (path == null || path.isBlank()) {
            throw new IllegalStateException("启用 gRPC TLS 时必须配置 " + property);
        }
    }
}
