package com.secureshare.dto;

import com.secureshare.model.AuditLog;
import java.time.Instant;

public record AuditEntryResponse(Long logId, Instant timestamp, String action, String status, String ipAddress,
                                 Long userId, String userEmail, Long fileId, String fileName) {
    public static AuditEntryResponse from(AuditLog a) {
        return new AuditEntryResponse(
                a.getLogId(), a.getTimestamp(), a.getAction(), a.getStatus(), a.getIpAddress(),
                a.getUser() == null ? null : a.getUser().getUserId(),
                a.getUser() == null ? null : a.getUser().getEmail(),
                a.getFile() == null ? null : a.getFile().getFileId(),
                a.getFile() == null ? null : a.getFile().getFileName());
    }
}
