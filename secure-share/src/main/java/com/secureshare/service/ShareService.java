package com.secureshare.service;

import com.secureshare.crypto.CryptoException;
import com.secureshare.crypto.CryptoService;
import com.secureshare.dto.ShareInfoResponse;
import com.secureshare.dto.ShareRecipient;
import com.secureshare.dto.ShareRequest;
import com.secureshare.dto.SharedFileResponse;
import com.secureshare.exception.ApiException;
import com.secureshare.model.FileEntity;
import com.secureshare.model.FileShare;
import com.secureshare.model.SharePermission;
import com.secureshare.model.ShareStatus;
import com.secureshare.model.User;
import com.secureshare.repository.FileRepository;
import com.secureshare.repository.FileShareRepository;
import com.secureshare.repository.UserRepository;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.stereotype.Service;

/**
 * Sharing is zero-trust too: the owner's CLIENT unwraps its own copy of the session key and re-wraps it
 * for every recipient. The server only stores the opaque wrapped keys and enforces who may fetch them.
 */
@Service
public class ShareService {

    private static final String NOT_OWNER = "Only the file owner can do this";

    private final FileRepository files;
    private final UserRepository users;
    private final FileShareRepository shares;
    private final CryptoService crypto;
    private final AuditService audit;

    public ShareService(FileRepository files, UserRepository users, FileShareRepository shares,
                        CryptoService crypto, AuditService audit) {
        this.files = files;
        this.users = users;
        this.shares = shares;
        this.crypto = crypto;
        this.audit = audit;
    }

    /** Creates (or re-activates) one share per recipient, all-or-nothing. */
    public List<ShareInfoResponse> share(Long ownerId, Long fileId, ShareRequest req, String ip) {
        FileEntity file = requireOwned(ownerId, fileId, "SHARE", ip);
        SharePermission permission = req.permission() == null ? SharePermission.DOWNLOAD : req.permission();
        Instant expiry = req.expiresAt();
        if (expiry != null && !expiry.isAfter(Instant.now())) {
            throw ApiException.badRequest("expiresAt must be in the future");
        }
        User owner = users.findById(ownerId).orElseThrow(() -> ApiException.unauthorized("Unknown user"));

        Set<String> seen = new HashSet<>();
        List<User> targets = new ArrayList<>();
        List<FileShare> toSave = new ArrayList<>();
        Instant now = Instant.now();

        for (ShareRecipient r : req.recipients()) {
            final String email = r.email().trim().toLowerCase(Locale.ROOT);
            if (!seen.add(email)) throw ApiException.badRequest("Duplicate recipient: " + email);
            User target = users.findByEmail(email)
                    .orElseThrow(() -> ApiException.notFound("No user with email " + email));
            if (target.getUserId().equals(ownerId)) {
                throw ApiException.badRequest("You already own this file; no need to share it with yourself");
            }
            checkWrappedKeyShape(r.wrappedKey(), target);

            FileShare s = shares.findByFile_FileIdAndRecipient_UserId(fileId, target.getUserId())
                    .orElseGet(FileShare::new);                       // existing row = re-grant after revoke/expiry
            s.setFile(file);
            s.setSender(owner);
            s.setRecipient(target);
            s.setPermission(permission);
            s.setExpiryDate(expiry);
            s.setStatus(ShareStatus.ACTIVE);
            s.setWrappedKey(r.wrappedKey().trim());
            s.setShareDate(now);
            targets.add(target);
            toSave.add(s);
        }

        List<FileShare> saved = shares.saveAll(toSave);                // one transaction
        List<ShareInfoResponse> out = new ArrayList<>();
        for (int i = 0; i < saved.size(); i++) {
            FileShare s = saved.get(i);
            User t = targets.get(i);
            audit.log(ownerId, fileId, "SHARE", ip, "SUCCESS");
            out.add(new ShareInfoResponse(s.getShareId(), t.getUserId(), t.getEmail(),
                    permission, ShareStatus.ACTIVE, expiry, now));
        }
        return out;
    }

    /** Immediately blocks the recipient's future bundle/download requests. */
    public ShareInfoResponse revoke(Long ownerId, Long fileId, String email, String ip) {
        requireOwned(ownerId, fileId, "REVOKE", ip);
        User target = users.findByEmail(email.trim().toLowerCase(Locale.ROOT))
                .orElseThrow(() -> ApiException.notFound("No user with that email"));
        FileShare s = shares.findByFile_FileIdAndRecipient_UserId(fileId, target.getUserId())
                .orElseThrow(() -> ApiException.notFound("This file is not shared with that user"));
        s.setStatus(ShareStatus.REVOKED);
        s = shares.save(s);
        audit.log(ownerId, fileId, "REVOKE", ip, "SUCCESS");
        return new ShareInfoResponse(s.getShareId(), target.getUserId(), target.getEmail(),
                s.getPermission(), s.getStatus(), s.getExpiryDate(), s.getShareDate());
    }

    /** Owner's view: who has (or had) access. ACTIVE shares past their expiry are reported as EXPIRED. */
    public List<ShareInfoResponse> listShares(Long ownerId, Long fileId, String ip) {
        requireOwned(ownerId, fileId, "LIST_SHARES", ip);
        Instant now = Instant.now();
        return shares.findAllForFile(fileId).stream().map(s -> {
            ShareStatus effective = s.getStatus();
            if (effective == ShareStatus.ACTIVE && s.getExpiryDate() != null && !s.getExpiryDate().isAfter(now)) {
                effective = ShareStatus.EXPIRED;
            }
            return new ShareInfoResponse(s.getShareId(), s.getRecipient().getUserId(), s.getRecipient().getEmail(),
                    s.getPermission(), effective, s.getExpiryDate(), s.getShareDate());
        }).toList();
    }

    public List<SharedFileResponse> sharedWithMe(Long userId) {
        return shares.findActiveForRecipient(userId, Instant.now()).stream().map(s -> {
            FileEntity f = s.getFile();
            return new SharedFileResponse(f.getFileId(), f.getFileName(), f.getFileType(), f.getFileSize(),
                    f.getOwner().getFullName(), f.getOwner().getEmail(),
                    s.getPermission(), s.getExpiryDate(), s.getShareDate());
        }).toList();
    }

    // ------------------------------------------------------------------ helpers

    private FileEntity requireOwned(Long userId, Long fileId, String action, String ip) {
        FileEntity f = files.findWithOwner(fileId).orElse(null);
        if (f == null || !f.getOwner().getUserId().equals(userId)) {
            audit.log(userId, f == null ? null : fileId, action, ip, "FAILURE");
            throw ApiException.forbidden(NOT_OWNER);       // same answer whether the file exists or not
        }
        return f;
    }

    /** The server cannot open a wrapped key, but it can reject obviously broken ones. */
    private void checkWrappedKeyShape(String wrappedKeyB64, User target) {
        try {
            RSAPublicKey key = (RSAPublicKey) crypto.decodePublicKey(target.getPublicKey());
            int expected = (key.getModulus().bitLength() + 7) / 8;
            if (crypto.decodeBytes(wrappedKeyB64.trim()).length != expected) {
                throw ApiException.badRequest("wrappedKey for " + target.getEmail() + " has the wrong length");
            }
        } catch (CryptoException e) {
            throw ApiException.badRequest("wrappedKey for " + target.getEmail() + " is not valid Base64");
        }
    }
}
