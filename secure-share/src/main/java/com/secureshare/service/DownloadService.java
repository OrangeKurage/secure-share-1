package com.secureshare.service;

import com.secureshare.dto.BundleResponse;
import com.secureshare.dto.ReceiptOutcome;
import com.secureshare.exception.ApiException;
import com.secureshare.model.FileEntity;
import com.secureshare.model.FileShare;
import com.secureshare.model.ShareStatus;
import com.secureshare.model.SharePermission;
import com.secureshare.repository.FileRepository;
import com.secureshare.repository.FileShareRepository;
import java.io.IOException;
import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

/**
 * Releases ciphertext + the caller's own wrapped key to owners and ACTIVE, unexpired recipients only.
 * Decryption, integrity (AES-GCM) and signature checks happen on the client; the client then reports
 * the outcome via {@link #receipt} so the audit log records it.
 */
@Service
public class DownloadService {

    private static final String DENIED = "You do not have access to this file";

    private final FileRepository files;
    private final FileShareRepository shares;
    private final FileStorageService storage;
    private final AuditService audit;

    public DownloadService(FileRepository files, FileShareRepository shares,
                           FileStorageService storage, AuditService audit) {
        this.files = files;
        this.shares = shares;
        this.storage = storage;
        this.audit = audit;
    }

    private record FileAccess(FileEntity file, String wrappedKey, SharePermission permission, Instant expiry) {}

    /** Owner, or recipient with an ACTIVE share that has not expired. Otherwise 403 + audit FAILURE. */
    private FileAccess resolveAccess(Long userId, Long fileId, String action, String ip) {
        FileEntity f = files.findWithOwner(fileId).orElse(null);
        if (f == null) {
            audit.log(userId, null, action, ip, "FAILURE");
            throw ApiException.forbidden(DENIED);          // 403 for "missing" too: no file-id enumeration
        }
        if (f.getOwner().getUserId().equals(userId)) {
            return new FileAccess(f, f.getEncryptedAesKey(), SharePermission.DOWNLOAD, null);
        }
        FileShare s = shares.findByFile_FileIdAndRecipient_UserId(fileId, userId).orElse(null);
        boolean allowed = s != null
                && s.getStatus() == ShareStatus.ACTIVE
                && (s.getExpiryDate() == null || s.getExpiryDate().isAfter(Instant.now()));
        if (!allowed) {
            audit.log(userId, fileId, action, ip, "FAILURE");
            throw ApiException.forbidden(DENIED);
        }
        return new FileAccess(f, s.getWrappedKey(), s.getPermission(), s.getExpiryDate());
    }

    /** Metadata + the caller's wrapped key + sender's public key. Works for VIEW and DOWNLOAD shares. */
    public BundleResponse bundle(Long userId, Long fileId, String ip) {
        FileAccess a = resolveAccess(userId, fileId, "VIEW", ip);
        FileEntity f = a.file();
        audit.log(userId, fileId, "VIEW", ip, "SUCCESS");
        return new BundleResponse(f.getFileId(), f.getFileName(), f.getFileType(), f.getFileSize(),
                f.getSha256Hash(), f.getSignature(), a.wrappedKey(),
                f.getOwner().getUserId(), f.getOwner().getFullName(), f.getOwner().getEmail(),
                f.getOwner().getPublicKey(), a.permission(), a.expiry(), f.getUploadDate());
    }

    /** The encrypted blob (IV || ciphertext || tag). Requires DOWNLOAD permission. */
    public byte[] download(Long userId, Long fileId, String ip) {
        FileAccess a = resolveAccess(userId, fileId, "DOWNLOAD", ip);
        if (a.permission() != SharePermission.DOWNLOAD) {
            audit.log(userId, fileId, "DOWNLOAD", ip, "FAILURE");
            throw ApiException.forbidden("This share is view-only; downloading is not permitted");
        }
        try {
            byte[] blob = storage.read(a.file().getStoragePath());
            audit.log(userId, fileId, "DOWNLOAD", ip, "SUCCESS");
            return blob;
        } catch (IOException e) {
            audit.log(userId, fileId, "DOWNLOAD", ip, "FAILURE");
            throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, "Stored file could not be read");
        }
    }

    /** Client-reported result of decrypt + verify. Recorded as action VERIFY. */
    public void receipt(Long userId, Long fileId, ReceiptOutcome outcome, String ip) {
        resolveAccess(userId, fileId, "VERIFY", ip);
        audit.log(userId, fileId, "VERIFY", ip, outcome.name());
    }
}
