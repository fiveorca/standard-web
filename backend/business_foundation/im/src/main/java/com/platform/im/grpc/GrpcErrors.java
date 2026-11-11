package com.platform.im.grpc;

import com.platform.im.shared.ApiException;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;

/**
 * 统一 HTTP/领域错误码到 gRPC Status 的映射。
 */
public final class GrpcErrors {
    private GrpcErrors() {
    }

    public static Status status(int code) {
        return switch (code) {
            case 40001 -> Status.INVALID_ARGUMENT;
            case 40101 -> Status.UNAUTHENTICATED;
            case 40301 -> Status.PERMISSION_DENIED;
            case 40401 -> Status.NOT_FOUND;
            case 40901 -> Status.ALREADY_EXISTS;
            case 41301 -> Status.RESOURCE_EXHAUSTED;
            case 42201 -> Status.INVALID_ARGUMENT;
            case 42901 -> Status.RESOURCE_EXHAUSTED;
            case 50201 -> Status.UNAVAILABLE;
            case 50301 -> Status.UNAVAILABLE;
            default -> Status.INTERNAL;
        };
    }

    public static StatusRuntimeException toException(ApiException exception) {
        Metadata trailers = new Metadata();
        trailers.put(Metadata.Key.of("error-code", Metadata.ASCII_STRING_MARSHALLER),
                String.valueOf(exception.code()));
        trailers.put(Metadata.Key.of("error-type", Metadata.ASCII_STRING_MARSHALLER),
                exception.error());
        return status(exception.code())
                .withDescription(exception.code() + ":" + exception.getMessage())
                .asRuntimeException(trailers);
    }

    public static StatusRuntimeException map(Throwable throwable) {
        if (throwable instanceof ApiException apiException) {
            return toException(apiException);
        }
        if (throwable instanceof StatusRuntimeException statusRuntimeException) {
            return statusRuntimeException;
        }
        return Status.INTERNAL
                .withDescription("50001:服务内部错误: " + throwable.getMessage())
                .asRuntimeException();
    }
}
