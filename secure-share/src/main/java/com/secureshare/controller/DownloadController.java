package com.secureshare.controller;

import com.secureshare.dto.BundleResponse;
import com.secureshare.dto.ReceiptRequest;
import com.secureshare.security.AuthenticatedUser;
import com.secureshare.service.DownloadService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/files")
public class DownloadController {

    private final DownloadService downloadService;

    public DownloadController(DownloadService downloadService) {
        this.downloadService = downloadService;
    }

    @GetMapping("/{fileId}/bundle")
    public BundleResponse bundle(@AuthenticationPrincipal AuthenticatedUser user,
                                 @PathVariable("fileId") Long fileId, HttpServletRequest http) {
        return downloadService.bundle(user.userId(), fileId, http.getRemoteAddr());
    }

    @GetMapping("/{fileId}/download")
    public ResponseEntity<byte[]> download(@AuthenticationPrincipal AuthenticatedUser user,
                                           @PathVariable("fileId") Long fileId, HttpServletRequest http) {
        byte[] blob = downloadService.download(user.userId(), fileId, http.getRemoteAddr());
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"file-" + fileId + ".enc\"")
                .body(blob);
    }

    @PostMapping("/{fileId}/receipt")
    public ResponseEntity<Void> receipt(@AuthenticationPrincipal AuthenticatedUser user,
                                        @PathVariable("fileId") Long fileId,
                                        @Valid @RequestBody ReceiptRequest req, HttpServletRequest http) {
        downloadService.receipt(user.userId(), fileId, req.outcome(), http.getRemoteAddr());
        return ResponseEntity.noContent().build();
    }
}
