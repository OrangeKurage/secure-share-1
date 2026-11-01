package com.secureshare.dto;

/** Everything a client needs to decrypt and verify a file locally. All binary values are Base64. */
public record DownloadBundle(Long fileId, String fileName, String fileType, long fileSize,
                             String sha256Hash, String signature, String wrappedKey,
                             String blob, String senderEmail, String senderPublicKey) {}
