package com.platform.im.grpc;

import com.platform.im.application.MqttPublishService;
import com.platform.im.grpc.proto.mqtt.BatchPublishResponse;
import com.platform.im.grpc.proto.mqtt.BatchPublishToDevicesRequest;
import com.platform.im.grpc.proto.mqtt.MqttMessageServiceGrpc;
import com.platform.im.grpc.proto.mqtt.PublishResponse;
import com.platform.im.grpc.proto.mqtt.PublishResult;
import com.platform.im.grpc.proto.mqtt.PublishToDeviceRequest;
import com.platform.im.grpc.proto.mqtt.PublishToTopicRequest;
import io.grpc.stub.StreamObserver;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class MqttMessageGrpcService extends MqttMessageServiceGrpc.MqttMessageServiceImplBase {
    private final MqttPublishService publishService;

    public MqttMessageGrpcService(MqttPublishService publishService) {
        this.publishService = publishService;
    }

    @Override
    public void publishToDevice(PublishToDeviceRequest request, StreamObserver<PublishResponse> observer) {
        try {
            UUID tenantId = GrpcSupport.tenant(request.getTenantId(), GrpcSupport.principal());
            MqttPublishService.PublishOutcome outcome = publishService.publishToDevice(
                    tenantId,
                    request.getDeviceId(),
                    request.getMessageId(),
                    request.getPayload().toByteArray(),
                    request.getContentType(),
                    request.getQos(),
                    request.getRetained(),
                    request.getMessageExpiryInterval() == 0 ? null : (long) request.getMessageExpiryInterval(),
                    "GRPC");
            observer.onNext(response(outcome));
            observer.onCompleted();
        } catch (Throwable throwable) {
            observer.onError(GrpcErrors.map(throwable));
        }
    }

    @Override
    public void batchPublishToDevices(BatchPublishToDevicesRequest request,
                                      StreamObserver<BatchPublishResponse> observer) {
        try {
            UUID tenantId = GrpcSupport.tenant(request.getTenantId(), GrpcSupport.principal());
            MqttPublishService.BatchOutcome outcome = publishService.batchPublishToDevices(
                    tenantId,
                    request.getDeviceIdsList(),
                    request.getMessageId(),
                    request.getPayload().toByteArray(),
                    request.getContentType(),
                    request.getQos(),
                    request.getRetained(),
                    request.getMessageExpiryInterval() == 0 ? null : (long) request.getMessageExpiryInterval(),
                    "GRPC");
            BatchPublishResponse.Builder builder = BatchPublishResponse.newBuilder()
                    .setTotal(outcome.total())
                    .setSuccessCount(outcome.successCount())
                    .setFailureCount(outcome.failureCount());
            for (MqttPublishService.PublishOutcome item : outcome.results()) {
                builder.addResults(PublishResult.newBuilder()
                        .setDeviceId(item.deviceId() == null ? "" : item.deviceId())
                        .setTopic(item.record() == null ? "" : item.record().topic)
                        .setSuccess(item.success())
                        .setCode(item.code() == null ? "" : item.code())
                        .setMessage(item.message() == null ? "" : item.message())
                        .setMessageId(item.record() == null ? "" : item.record().messageId)
                        .setRecordId(item.record() == null ? "" : item.record().id.toString())
                        .build());
            }
            observer.onNext(builder.build());
            observer.onCompleted();
        } catch (Throwable throwable) {
            observer.onError(GrpcErrors.map(throwable));
        }
    }

    @Override
    public void publishToTopic(PublishToTopicRequest request, StreamObserver<PublishResponse> observer) {
        try {
            UUID tenantId = GrpcSupport.tenant(request.getTenantId(), GrpcSupport.principal());
            MqttPublishService.PublishOutcome outcome = publishService.publishToTopic(
                    tenantId,
                    request.getTopic(),
                    request.getMessageId(),
                    request.getPayload().toByteArray(),
                    request.getContentType(),
                    request.getQos(),
                    request.getRetained(),
                    request.getMessageExpiryInterval() == 0 ? null : (long) request.getMessageExpiryInterval(),
                    "GRPC");
            observer.onNext(response(outcome));
            observer.onCompleted();
        } catch (Throwable throwable) {
            observer.onError(GrpcErrors.map(throwable));
        }
    }

    private static PublishResponse response(MqttPublishService.PublishOutcome outcome) {
        return PublishResponse.newBuilder()
                .setSuccess(outcome.success())
                .setCode(outcome.code() == null ? "" : outcome.code())
                .setMessage(outcome.message() == null ? "" : outcome.message())
                .setRecordId(outcome.record() == null ? "" : outcome.record().id.toString())
                .setTopic(outcome.record() == null ? "" : outcome.record().topic)
                .setMessageId(outcome.record() == null ? "" : outcome.record().messageId)
                .build();
    }
}
