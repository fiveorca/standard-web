package com.platform.im.infrastructure.mqtt;

public class MqttPublishException extends RuntimeException {
    private final String code;

    public MqttPublishException(String code, String message) {
        super(message);
        this.code = code;
    }

    public MqttPublishException(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
