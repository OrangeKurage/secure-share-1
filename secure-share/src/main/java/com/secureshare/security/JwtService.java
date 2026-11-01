package com.secureshare.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import javax.crypto.SecretKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    private final SecretKey key;
    private final long expiryMinutes;

    public JwtService(@Value("${app.jwt.secret}") String secret,
                      @Value("${app.jwt.expiry-minutes}") long expiryMinutes) {
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 32) {
            throw new IllegalStateException("app.jwt.secret must be at least 32 bytes long");
        }
        if (secret.startsWith("change-me")) {
            log.warn("JWT secret is still the built-in default. Set the JWT_SECRET environment variable before exposing this server.");
        }
        this.key = Keys.hmacShaKeyFor(bytes);
        this.expiryMinutes = expiryMinutes;
    }

    public long expiryMinutes() { return expiryMinutes; }

    /** subject = user id, jti = id of the row in the Session table. */
    public String issue(long userId, long sessionId, Instant issuedAt, Instant expiresAt) {
        return Jwts.builder()
                .subject(Long.toString(userId))
                .id(Long.toString(sessionId))
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(expiresAt))
                .signWith(key)
                .compact();
    }

    /** @throws JwtException if the token is malformed, tampered with or expired. */
    public Claims parse(String token) throws JwtException {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
    }
}
