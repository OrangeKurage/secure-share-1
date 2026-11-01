package com.secureshare.dto;

import com.secureshare.model.SharePermission;
import java.time.Instant;

public record SharedFileResponse(Long fileId, String fileName, String fileType, long fileSize,
                                 String ownerName, String ownerEmail,
                                 SharePermission permission, Instant expiryDate, Instant shareDate) {}
