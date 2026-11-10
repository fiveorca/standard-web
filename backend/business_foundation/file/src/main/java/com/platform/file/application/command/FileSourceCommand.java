package com.platform.file.application.command;

public record FileSourceCommand(
        String code,
        String name,
        String description,
        Boolean enabled) {
}
