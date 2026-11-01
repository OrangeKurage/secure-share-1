package com.secureshare.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "sessions")
public class Session {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "session_id")
    private Long sessionId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /** SHA-256 hex of the issued JWT. The raw token is returned once at login and is not stored. */
    @Column(name = "jwt_token", nullable = false, columnDefinition = "TEXT")
    private String jwtToken;

    @Column(name = "login_time", nullable = false, updatable = false)
    private Instant loginTime;

    @Column(name = "expiry_time", nullable = false)
    private Instant expiryTime;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private SessionStatus status = SessionStatus.ACTIVE;

    @PrePersist
    void onCreate() {
        if (loginTime == null) loginTime = Instant.now();
    }

    // ---- accessors ----
    public Long getSessionId() { return sessionId; }
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
    public String getJwtToken() { return jwtToken; }
    public void setJwtToken(String jwtToken) { this.jwtToken = jwtToken; }
    public Instant getLoginTime() { return loginTime; }
    public void setLoginTime(Instant loginTime) { this.loginTime = loginTime; }
    public Instant getExpiryTime() { return expiryTime; }
    public void setExpiryTime(Instant expiryTime) { this.expiryTime = expiryTime; }
    public SessionStatus getStatus() { return status; }
    public void setStatus(SessionStatus status) { this.status = status; }
}
