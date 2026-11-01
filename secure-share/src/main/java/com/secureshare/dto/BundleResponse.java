package com.secureshare.dto;

import com.secureshare.model.SharePermission;
import java.time.Instant;

/**
 * Everything a client needs, besides the ciphertext blob itself, to decrypt and verify a file:
 * the caller's own wrapped key, the signature, the hash and the sender's public key.
 */
public record BundleResponse(Long fileId, String fileName, String fileType, long fileSize,
                             String sha256Hash, String signature, String wrappedKey,
                             Long ownerId, String ownerName, String ownerEmail, String ownerPublicKey,
                             SharePermission permission, Instant expiresAt, Instant uploadDate) {}
