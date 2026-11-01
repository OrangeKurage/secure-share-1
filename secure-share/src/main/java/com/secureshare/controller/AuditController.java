package com.secureshare.controller;

import com.secureshare.dto.AuditEntryResponse;
import com.secureshare.security.AuthenticatedUser;
import com.secureshare.service.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/audit-log")
public class AuditController {

    private final AuditService auditService;

    public AuditController(AuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping("/me")
    public List<AuditEntryResponse> me(@AuthenticationPrincipal AuthenticatedUser user,
                                       @RequestParam(value = "limit", defaultValue = "100") int limit) {
        return auditService.myLog(user.userId(), limit);
    }

    @GetMapping("/file/{fileId}")
    public List<AuditEntryResponse> forFile(@AuthenticationPrincipal AuthenticatedUser user,
                                            @PathVariable("fileId") Long fileId,
                                            @RequestParam(value = "limit", defaultValue = "100") int limit,
                                            HttpServletRequest http) {
        return auditService.fileLog(user.userId(), fileId, limit, http.getRemoteAddr());
    }
}
