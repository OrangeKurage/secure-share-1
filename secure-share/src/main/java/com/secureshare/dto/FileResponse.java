package com.secureshare.dto;

import com.secureshare.model.FileEntity;
import java.time.Instant;

public record FileResponse(Long fileId, String fileName, String fileType, long fileSize,
                           String sha256Hash, Instant uploadDate) {
    public static FileResponse from(FileEntity f) {
        return new FileResponse(f.getFileId(), f.getFileName(), f.getFileType(), f.getFileSize(),
                f.getSha256Hash(), f.getUploadDate());
    }
}
