package com.secureshare.dto;

import com.secureshare.model.AuditLog;
import java.time.Instant;

public record AuditLogResponse(Long logId, Long userId, String userEmail, Long fileId,
                               String action, String ipAddress, Instant timestamp, String status) {
    public static AuditLogResponse from(AuditLog a) {
        return new AuditLogResponse(
                a.getLogId(),
                a.getUser() == null ? null : a.getUser().getUserId(),
                a.getUser() == null ? null : a.getUser().getEmail(),
                a.getFile() == null ? null : a.getFile().getFileId(),
                a.getAction(), a.getIpAddress(), a.getTimestamp(), a.getStatus());
    }
}
