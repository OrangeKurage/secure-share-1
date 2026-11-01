package com.secureshare.model;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "files")
public class FileEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "file_id")
    private Long fileId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;

    @Column(name = "file_name", nullable = false, length = 255)
    private String fileName;

    @Column(name = "file_type", length = 20)
    private String fileType;

    /** Path of the encrypted blob (IV || ciphertext || GCM tag) under app.storage.path. */
    @Column(name = "storage_path", nullable = false, length = 255)
    private String storagePath;

    @Column(name = "upload_date", nullable = false, updatable = false)
    private Instant uploadDate;

    /** The owner's own RSA-OAEP-wrapped copy of the AES session key (Base64). */
    @Column(name = "encrypted_aes_key", nullable = false, columnDefinition = "TEXT")
    private String encryptedAesKey;

    /** Hex SHA-256 of the original plaintext. */
    @Column(name = "sha256_hash", nullable = false, length = 64)
    private String sha256Hash;

    /** RSA-PSS signature over the plaintext hash (Base64). */
    @Column(name = "signature", nullable = false, columnDefinition = "TEXT")
    private String signature;

    @Column(name = "file_size", nullable = false)
    private long fileSize;

    @OneToMany(mappedBy = "file")
    private List<FileShare> shares = new ArrayList<>();

    @OneToMany(mappedBy = "file")
    private List<AuditLog> auditLogs = new ArrayList<>();

    @PrePersist
    void onCreate() {
        if (uploadDate == null) uploadDate = Instant.now();
    }

    // ---- accessors ----
    public Long getFileId() { return fileId; }
    public User getOwner() { return owner; }
    public void setOwner(User owner) { this.owner = owner; }
    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }
    public String getFileType() { return fileType; }
    public void setFileType(String fileType) { this.fileType = fileType; }
    public String getStoragePath() { return storagePath; }
    public void setStoragePath(String storagePath) { this.storagePath = storagePath; }
    public Instant getUploadDate() { return uploadDate; }
    public void setUploadDate(Instant uploadDate) { this.uploadDate = uploadDate; }
    public String getEncryptedAesKey() { return encryptedAesKey; }
    public void setEncryptedAesKey(String encryptedAesKey) { this.encryptedAesKey = encryptedAesKey; }
    public String getSha256Hash() { return sha256Hash; }
    public void setSha256Hash(String sha256Hash) { this.sha256Hash = sha256Hash; }
    public String getSignature() { return signature; }
    public void setSignature(String signature) { this.signature = signature; }
    public long getFileSize() { return fileSize; }
    public void setFileSize(long fileSize) { this.fileSize = fileSize; }
    public List<FileShare> getShares() { return shares; }
    public List<AuditLog> getAuditLogs() { return auditLogs; }
}
