package com.platform.im.grpc;

import com.platform.im.config.AppProperties;
import com.platform.im.infrastructure.ratelimit.RequestRateLimiter;
import com.platform.im.security.AuthPrincipal;
import com.platform.im.security.JwtVerifier;
import com.platform.im.shared.ApiException;
import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * gRPC 调用认证：支持平台 JWT 与服务间内部令牌，健康检查端点放行。
 */
@Component
@Order(10)
public class GrpcAuthInterceptor implements ServerInterceptor {
    public static final Context.Key<AuthPrincipal> PRINCIPAL =
            Context.key("im.grpc.principal");

    private static final Metadata.Key<String> AUTHORIZATION =
            Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
    private static final Metadata.Key<String> INTERNAL_TOKEN =
            Metadata.Key.of("x-internal-token", Metadata.ASCII_STRING_MARSHALLER);

    private final AppProperties props;
    private final JwtVerifier jwtVerifier;
    private final RequestRateLimiter rateLimiter;

    public GrpcAuthInterceptor(AppProperties props, JwtVerifier jwtVerifier,
                               RequestRateLimiter rateLimiter) {
        this.props = props;
        this.jwtVerifier = jwtVerifier;
        this.rateLimiter = rateLimiter;
    }

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        String method = call.getMethodDescriptor().getFullMethodName();
        if (!props.grpc.authEnabled) {
            Context context = Context.current().withValue(PRINCIPAL, AuthPrincipal.system("grpc-auth-disabled"));
            return Contexts.interceptCall(context, call, headers, next);
        }
        if (method.startsWith("grpc.health.v1.Health")) {
            Context context = Context.current().withValue(PRINCIPAL, AuthPrincipal.system("health-check"));
            return Contexts.interceptCall(context, call, headers, next);
        }
        try {
            AuthPrincipal principal = authenticate(headers);
            rateLimiter.checkGrpc(principal.subject());
            Context context = Context.current().withValue(PRINCIPAL, principal);
            return Contexts.interceptCall(context, call, headers, next);
        } catch (ApiException exception) {
            call.close(GrpcErrors.toException(exception).getStatus(), new Metadata());
            return new ServerCall.Listener<>() {
            };
        } catch (RuntimeException exception) {
            call.close(Status.UNAUTHENTICATED.withDescription(exception.getMessage()), new Metadata());
            return new ServerCall.Listener<>() {
            };
        }
    }

    private AuthPrincipal authenticate(Metadata headers) {
        String internalToken = headers.get(INTERNAL_TOKEN);
        if (internalToken != null && internalTokenValid(internalToken)) {
            return AuthPrincipal.internal();
        }
        String authorization = headers.get(AUTHORIZATION);
        if (authorization == null || authorization.isBlank()) {
            throw ApiException.unauthorized("缺少 gRPC 调用凭证");
        }
        String value = authorization.trim();
        if (value.regionMatches(true, 0, "Bearer ", 0, 7)) {
            value = value.substring(7).trim();
        }
        return jwtVerifier.verify(value);
    }

    private boolean internalTokenValid(String provided) {
        String expected = props.security.internalToken;
        if (expected == null || expected.isBlank() || provided == null) {
            return false;
        }
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                provided.getBytes(StandardCharsets.UTF_8));
    }
}
