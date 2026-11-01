package com.secureshare.dto;

import java.time.Instant;

public record FileSummary(Long fileId, String fileName, String fileType, long fileSize,
                          String sha256Hash, Instant uploadDate) {}
