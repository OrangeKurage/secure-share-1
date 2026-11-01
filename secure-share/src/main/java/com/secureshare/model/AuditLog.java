package com.secureshare.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_log")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "log_id")
    private Long logId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "file_id")
    private FileEntity file;

    @Column(name = "action", nullable = false, length = 50)
    private String action;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "event_time", nullable = false, updatable = false)
    private Instant timestamp;

    @Column(name = "status", length = 20)
    private String status;

    @PrePersist
    void onCreate() {
        if (timestamp == null) timestamp = Instant.now();
    }

    // ---- accessors ----
    public Long getLogId() { return logId; }
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
    public FileEntity getFile() { return file; }
    public void setFile(FileEntity file) { this.file = file; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
}
