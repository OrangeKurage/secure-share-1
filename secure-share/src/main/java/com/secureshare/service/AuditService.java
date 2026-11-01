package com.secureshare.service;

import com.secureshare.dto.AuditEntryResponse;
import com.secureshare.exception.ApiException;
import com.secureshare.model.AuditLog;
import com.secureshare.model.FileEntity;
import com.secureshare.repository.AuditLogRepository;
import com.secureshare.repository.FileRepository;
import com.secureshare.repository.UserRepository;
import java.util.List;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

@Service
public class AuditService {

    private static final int MAX_LIMIT = 500;

    private final AuditLogRepository logs;
    private final UserRepository users;
    private final FileRepository files;

    public AuditService(AuditLogRepository logs, UserRepository users, FileRepository files) {
        this.logs = logs;
        this.users = users;
        this.files = files;
    }

    /** userId / fileId may be null (e.g. a failed login for an unknown email). */
    public void log(Long userId, Long fileId, String action, String ip, String status) {
        AuditLog entry = new AuditLog();
        if (userId != null) entry.setUser(users.getReferenceById(userId));
        if (fileId != null) entry.setFile(files.getReferenceById(fileId));
        entry.setAction(action);
        entry.setIpAddress(ip);
        entry.setStatus(status);
        logs.save(entry);
    }

    /** The caller's own activity, newest first. */
    public List<AuditEntryResponse> myLog(Long userId, int limit) {
        return logs.findForUser(userId, PageRequest.of(0, clamp(limit))).stream()
                .map(AuditEntryResponse::from).toList();
    }

    /** Every user's activity on one file. Owner only; refusals are themselves audited. */
    public List<AuditEntryResponse> fileLog(Long userId, Long fileId, int limit, String ip) {
        FileEntity f = files.findWithOwner(fileId).orElse(null);
        if (f == null || !f.getOwner().getUserId().equals(userId)) {
            log(userId, f == null ? null : fileId, "AUDIT_VIEW", ip, "FAILURE");
            throw ApiException.forbidden("Only the file owner can view its audit log");
        }
        return logs.findForFile(fileId, PageRequest.of(0, clamp(limit))).stream()
                .map(AuditEntryResponse::from).toList();
    }

    private static int clamp(int limit) {
        return Math.max(1, Math.min(limit, MAX_LIMIT));
    }
}
