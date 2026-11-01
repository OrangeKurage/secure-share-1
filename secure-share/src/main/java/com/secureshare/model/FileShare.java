package com.secureshare.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "file_share",
       uniqueConstraints = @UniqueConstraint(columnNames = {"file_id", "recipient_id"}))
public class FileShare {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "share_id")
    private Long shareId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "file_id", nullable = false)
    private FileEntity file;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "sender_id", nullable = false)
    private User sender;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "recipient_id", nullable = false)
    private User recipient;

    @Enumerated(EnumType.STRING)
    @Column(name = "permission", nullable = false, length = 20)
    private SharePermission permission;

    @Column(name = "expiry_date")
    private Instant expiryDate;

    @Column(name = "share_date", nullable = false)
    private Instant shareDate;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private ShareStatus status = ShareStatus.ACTIVE;

    /** AES session key wrapped (RSA-OAEP) with the recipient's public key (Base64). */
    @Column(name = "wrapped_key", nullable = false, columnDefinition = "TEXT")
    private String wrappedKey;

    @PrePersist
    void onCreate() {
        if (shareDate == null) shareDate = Instant.now();
    }

    // ---- accessors ----
    public Long getShareId() { return shareId; }
    public FileEntity getFile() { return file; }
    public void setFile(FileEntity file) { this.file = file; }
    public User getSender() { return sender; }
    public void setSender(User sender) { this.sender = sender; }
    public User getRecipient() { return recipient; }
    public void setRecipient(User recipient) { this.recipient = recipient; }
    public SharePermission getPermission() { return permission; }
    public void setPermission(SharePermission permission) { this.permission = permission; }
    public Instant getExpiryDate() { return expiryDate; }
    public void setExpiryDate(Instant expiryDate) { this.expiryDate = expiryDate; }
    public Instant getShareDate() { return shareDate; }
    public void setShareDate(Instant shareDate) { this.shareDate = shareDate; }
    public ShareStatus getStatus() { return status; }
    public void setStatus(ShareStatus status) { this.status = status; }
    public String getWrappedKey() { return wrappedKey; }
    public void setWrappedKey(String wrappedKey) { this.wrappedKey = wrappedKey; }
}
