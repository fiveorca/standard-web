package com.platform.im.grpc;

import com.platform.im.application.EmailSendService;
import com.platform.im.grpc.proto.email.BatchSendEmailRequest;
import com.platform.im.grpc.proto.email.BatchSendEmailResponse;
import com.platform.im.grpc.proto.email.EmailServiceGrpc;
import com.platform.im.grpc.proto.email.EmailStatusResponse;
import com.platform.im.grpc.proto.email.EmailTaskResponse;
import com.platform.im.grpc.proto.email.GetEmailStatusRequest;
import com.platform.im.grpc.proto.email.SendEmailRequest;
import com.platform.im.web.dto.EmailDtos;
import io.grpc.stub.StreamObserver;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class EmailGrpcService extends EmailServiceGrpc.EmailServiceImplBase {
    private final EmailSendService sendService;

    public EmailGrpcService(EmailSendService sendService) {
        this.sendService = sendService;
    }

    @Override
    public void sendEmail(SendEmailRequest request, StreamObserver<EmailTaskResponse> observer) {
        try {
            UUID tenantId = GrpcSupport.tenant(request.getTenantId(), GrpcSupport.principal());
            EmailSendService.AcceptedTask task = sendService.accept(command(request, tenantId));
            observer.onNext(EmailTaskResponse.newBuilder()
                    .setTaskId(task.taskId().toString())
                    .setStatus(task.status().name())
                    .setAccepted(true)
                    .setCode("0")
                    .setMessage(task.created() ? "accepted" : "idempotent_replay")
                    .setRequestId(task.requestId() == null ? "" : task.requestId())
                    .build());
            observer.onCompleted();
        } catch (Throwable throwable) {
            observer.onError(GrpcErrors.map(throwable));
        }
    }

    @Override
    public void batchSendEmail(BatchSendEmailRequest request,
                               StreamObserver<BatchSendEmailResponse> observer) {
        try {
            List<EmailSendService.EmailSendCommand> commands = new ArrayList<>(request.getRequestsCount());
            for (SendEmailRequest item : request.getRequestsList()) {
                commands.add(command(item, GrpcSupport.tenant(item.getTenantId(), GrpcSupport.principal())));
            }
            EmailSendService.BatchResult result = sendService.acceptBatch(commands);
            BatchSendEmailResponse.Builder builder = BatchSendEmailResponse.newBuilder()
                    .setTotal(result.total())
                    .setAcceptedCount(result.acceptedCount());
            for (EmailSendService.BatchItem item : result.items()) {
                builder.addResults(EmailTaskResponse.newBuilder()
                        .setTaskId(item.taskId() == null ? "" : item.taskId().toString())
                        .setStatus(item.accepted() ? "PENDING" : "FAILED")
                        .setAccepted(item.accepted())
                        .setCode(item.code() == null ? "" : item.code())
                        .setMessage(item.message() == null ? "" : item.message())
                        .setRequestId(item.requestId() == null ? "" : item.requestId())
                        .build());
            }
            observer.onNext(builder.build());
            observer.onCompleted();
        } catch (Throwable throwable) {
            observer.onError(GrpcErrors.map(throwable));
        }
    }

    @Override
    public void getEmailStatus(GetEmailStatusRequest request,
                               StreamObserver<EmailStatusResponse> observer) {
        try {
            UUID tenantId = GrpcSupport.tenant(request.getTenantId(), GrpcSupport.principal());
            EmailDtos.EmailTaskView task = sendService.status(tenantId,
                    GrpcSupport.uuid(request.getTaskId(), "task_id"), request.getRequestId());
            EmailStatusResponse.Builder builder = EmailStatusResponse.newBuilder()
                    .setTaskId(task.id().toString())
                    .setRequestId(task.requestId() == null ? "" : task.requestId())
                    .setStatus(task.status().name())
                    .setAttempts(task.attemptCount())
                    .setLastError(task.lastErrorMessage() == null ? "" : task.lastErrorMessage())
                    .setProviderMessageId(task.providerMessageId() == null ? "" : task.providerMessageId())
                    .setAcceptedAt(format(task.acceptedAt()))
                    .setFinishedAt(format(task.finishedAt()));
            observer.onNext(builder.build());
            observer.onCompleted();
        } catch (Throwable throwable) {
            observer.onError(GrpcErrors.map(throwable));
        }
    }

    private EmailSendService.EmailSendCommand command(SendEmailRequest request, UUID tenantId) {
        List<EmailSendService.EmailAttachmentInput> attachments = new ArrayList<>();
        for (com.platform.im.grpc.proto.email.EmailAttachment attachment : request.getAttachmentsList()) {
            attachments.add(new EmailSendService.EmailAttachmentInput(
                    attachment.getFilename(),
                    attachment.getContentType(),
                    attachment.getContent().toByteArray()));
        }
        return new EmailSendService.EmailSendCommand(tenantId, request.getRequestId(),
                GrpcSupport.uuid(request.getSenderId(), "sender_id"),
                request.getToList(), request.getCcList(), request.getBccList(),
                request.getSubject(), request.getTextBody(), request.getHtmlBody(), attachments);
    }

    private static String format(Instant instant) {
        return instant == null ? "" : instant.toString();
    }
}
