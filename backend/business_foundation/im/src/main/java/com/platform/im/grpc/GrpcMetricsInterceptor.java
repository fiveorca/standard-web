package com.platform.im.grpc;

import io.grpc.ForwardingServerCall;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

/**
 * gRPC 请求指标：调用次数、状态与耗时。
 */
@Component
@Order(20)
public class GrpcMetricsInterceptor implements ServerInterceptor {
    private final MeterRegistry registry;

    public GrpcMetricsInterceptor(MeterRegistry registry) {
        this.registry = registry;
    }

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        String method = call.getMethodDescriptor().getFullMethodName();
        long start = System.nanoTime();
        AtomicLong ended = new AtomicLong();
        ServerCall<ReqT, RespT> wrapped = new ForwardingServerCall.SimpleForwardingServerCall<>(call) {
            @Override
            public void close(Status status, Metadata trailers) {
                if (ended.compareAndSet(0, 1)) {
                    Counter.builder("im.grpc.requests.total")
                            .tag("method", method)
                            .tag("status", status.getCode().name())
                            .register(registry)
                            .increment();
                    Timer.builder("im.grpc.request.duration")
                            .tag("method", method)
                            .register(registry)
                            .record(Duration.ofNanos(System.nanoTime() - start));
                }
                super.close(status, trailers);
            }
        };
        return next.startCall(wrapped, headers);
    }
}
