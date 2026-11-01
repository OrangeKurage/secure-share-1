package com.secureshare.controller;

import com.secureshare.dto.FileResponse;
import com.secureshare.exception.ApiException;
import com.secureshare.security.AuthenticatedUser;
import com.secureshare.service.FileService;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/files")
public class FileController {

    private final FileService fileService;

    public FileController(FileService fileService) {
        this.fileService = fileService;
    }

    /**
     * multipart/form-data. "file" is the already-encrypted blob (IV || ciphertext || tag);
     * everything else is metadata computed by the client.
     */
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<FileResponse> upload(
            @AuthenticationPrincipal AuthenticatedUser user,
            @RequestParam("file") MultipartFile file,
            @RequestParam("fileName") String fileName,
            @RequestParam(value = "fileType", required = false) String fileType,
            @RequestParam("sha256Hash") String sha256Hash,
            @RequestParam("signature") String signature,
            @RequestParam("encryptedAesKey") String encryptedAesKey,
            HttpServletRequest http) {
        byte[] blob;
        try {
            blob = file.getBytes();
        } catch (IOException e) {
            throw ApiException.badRequest("Could not read uploaded file");
        }
        var saved = fileService.upload(user.userId(), fileName, fileType, blob,
                sha256Hash, signature, encryptedAesKey, http.getRemoteAddr());
        return ResponseEntity.status(HttpStatus.CREATED).body(FileResponse.from(saved));
    }

    @GetMapping("/mine")
    public List<FileResponse> mine(@AuthenticationPrincipal AuthenticatedUser user) {
        return fileService.listOwned(user.userId()).stream().map(FileResponse::from).toList();
    }
}
