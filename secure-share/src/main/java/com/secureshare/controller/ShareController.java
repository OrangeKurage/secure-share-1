package com.secureshare.controller;

import com.secureshare.dto.RevokeRequest;
import com.secureshare.dto.ShareInfoResponse;
import com.secureshare.dto.ShareRequest;
import com.secureshare.dto.SharedFileResponse;
import com.secureshare.security.AuthenticatedUser;
import com.secureshare.service.ShareService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/files")
public class ShareController {

    private final ShareService shareService;

    public ShareController(ShareService shareService) {
        this.shareService = shareService;
    }

    @PostMapping("/{fileId}/share")
    public List<ShareInfoResponse> share(@AuthenticationPrincipal AuthenticatedUser user,
                                         @PathVariable("fileId") Long fileId,
                                         @Valid @RequestBody ShareRequest req, HttpServletRequest http) {
        return shareService.share(user.userId(), fileId, req, http.getRemoteAddr());
    }

    @PostMapping("/{fileId}/revoke")
    public ShareInfoResponse revoke(@AuthenticationPrincipal AuthenticatedUser user,
                                    @PathVariable("fileId") Long fileId,
                                    @Valid @RequestBody RevokeRequest req, HttpServletRequest http) {
        return shareService.revoke(user.userId(), fileId, req.email(), http.getRemoteAddr());
    }

    @GetMapping("/{fileId}/shares")
    public List<ShareInfoResponse> shares(@AuthenticationPrincipal AuthenticatedUser user,
                                          @PathVariable("fileId") Long fileId, HttpServletRequest http) {
        return shareService.listShares(user.userId(), fileId, http.getRemoteAddr());
    }

    @GetMapping("/shared-with-me")
    public List<SharedFileResponse> sharedWithMe(@AuthenticationPrincipal AuthenticatedUser user) {
        return shareService.sharedWithMe(user.userId());
    }
}
