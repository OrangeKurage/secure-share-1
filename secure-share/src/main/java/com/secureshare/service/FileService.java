package com.secureshare.service;

import com.secureshare.crypto.CryptoException;
import com.secureshare.crypto.CryptoService;
import com.secureshare.crypto.EncryptedPayload;
import com.secureshare.exception.ApiException;
import com.secureshare.model.FileEntity;
import com.secureshare.model.User;
import com.secureshare.repository.FileRepository;
import com.secureshare.repository.UserRepository;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;

/**
 * Zero-trust file storage: the CLIENT encrypts, hashes, signs and wraps keys.
 * This service only validates the shape of what it receives, checks that the signature really was
 * made by the uploader's registered key, and stores the opaque ciphertext.
 */
@Service
public class FileService {

    private static final Pattern SHA256_HEX = Pattern.compile("^[0-9a-f]{64}$");

    private final FileRepository files;
    private final UserRepository users;
    private final FileStorageService storage;
    private final CryptoService crypto;
    private final AuditService audit;

    public FileService(FileRepository files, UserRepository users, FileStorageService storage,
                       CryptoService crypto, AuditService audit) {
        this.files = files;
        this.users = users;
        this.storage = storage;
        this.crypto = crypto;
        this.audit = audit;
    }

    /**
     * @param blob               IV(12) || AES-GCM ciphertext || tag(16), produced by the client
     * @param sha256Hex          hex SHA-256 of the ORIGINAL plaintext
     * @param signatureB64       RSA-PSS signature over that hash, Base64
     * @param encryptedAesKeyB64 the uploader's own RSA-OAEP-wrapped copy of the session key, Base64
     */
    public FileEntity upload(Long ownerId, String fileName, String fileType, byte[] blob,
                             String sha256Hex, String signatureB64, String encryptedAesKeyB64, String ip) {
        User owner = users.findById(ownerId).orElseThrow(() -> ApiException.unauthorized("Unknown user"));

        String hash;
        try {
            hash = validate(owner, blob, sha256Hex, signatureB64, encryptedAesKeyB64);
        } catch (ApiException e) {
            audit.log(ownerId, null, "UPLOAD", ip, "FAILURE");
            throw e;
        }

        String storedName;
        try {
            storedName = storage.store(blob);
        } catch (IOException e) {
            throw new ApiException(org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR, "Could not store file");
        }

        FileEntity f = new FileEntity();
        f.setOwner(owner);
        f.setFileName(cleanFileName(fileName));
        f.setFileType(deriveType(fileType, f.getFileName()));
        f.setStoragePath(storedName);
        f.setEncryptedAesKey(encryptedAesKeyB64.trim());
        f.setSha256Hash(hash);
        f.setSignature(signatureB64.trim());
        f.setFileSize(blob.length - EncryptedPayload.IV_LENGTH - 16L);     // = plaintext size
        try {
            f = files.save(f);
        } catch (RuntimeException e) {
            storage.deleteQuietly(storedName);                              // no orphan blobs
            throw e;
        }
        audit.log(ownerId, f.getFileId(), "UPLOAD", ip, "SUCCESS");
        return f;
    }

    /** @return the normalised (lower-case) hash. */
    private String validate(User owner, byte[] blob, String sha256Hex, String signatureB64, String encKeyB64) {
        if (blob == null || blob.length < EncryptedPayload.IV_LENGTH + 16) {
            throw ApiException.badRequest("Encrypted file is empty or malformed");
        }
        String hash = sha256Hex == null ? "" : sha256Hex.trim().toLowerCase(Locale.ROOT);
        if (!SHA256_HEX.matcher(hash).matches()) {
            throw ApiException.badRequest("sha256Hash must be 64 hex characters");
        }
        if (signatureB64 == null || encKeyB64 == null) {
            throw ApiException.badRequest("signature and encryptedAesKey are required");
        }
        try {
            RSAPublicKey ownerKey = (RSAPublicKey) crypto.decodePublicKey(owner.getPublicKey());
            int rsaBytes = (ownerKey.getModulus().bitLength() + 7) / 8;
            byte[] signature = crypto.decodeBytes(signatureB64.trim());
            byte[] wrapped = crypto.decodeBytes(encKeyB64.trim());
            if (signature.length != rsaBytes) throw ApiException.badRequest("signature has the wrong length");
            if (wrapped.length != rsaBytes) throw ApiException.badRequest("encryptedAesKey has the wrong length");
            if (!crypto.verifySignature(signature, crypto.fromHex(hash), ownerKey)) {
                throw ApiException.unprocessable("Signature does not verify against your registered public key");
            }
        } catch (CryptoException e) {
            throw ApiException.badRequest("Malformed cryptographic field: " + e.getMessage());
        }
        return hash;
    }

    private static String cleanFileName(String name) {
        if (name == null || name.isBlank()) throw ApiException.badRequest("fileName is required");
        String n = name.replaceAll("[\\\\/]", "_").replaceAll("\\p{Cntrl}", "").trim();
        if (n.isEmpty()) throw ApiException.badRequest("fileName is required");
        return n.length() > 255 ? n.substring(0, 255) : n;
    }

    private static String deriveType(String given, String fileName) {
        String t = given;
        if (t == null || t.isBlank()) {
            int dot = fileName.lastIndexOf('.');
            t = (dot >= 0 && dot < fileName.length() - 1) ? fileName.substring(dot + 1) : null;
        }
        if (t == null) return null;
        t = t.trim().toLowerCase(Locale.ROOT);
        return t.length() > 20 ? t.substring(0, 20) : t;
    }

    public List<FileEntity> listOwned(Long ownerId) {
        return files.findByOwner_UserId(ownerId);
    }
}
