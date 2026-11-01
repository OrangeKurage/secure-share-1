package com.secureshare.service;

import com.secureshare.model.Session;
import com.secureshare.model.SessionStatus;
import com.secureshare.model.User;
import com.secureshare.repository.SessionRepository;
import com.secureshare.security.AuthenticatedUser;
import com.secureshare.security.JwtService;
import com.secureshare.security.TokenDigest;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import java.time.Instant;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SessionService {

    private final JwtService jwtService;
    private final SessionRepository sessions;

    public SessionService(JwtService jwtService, SessionRepository sessions) {
        this.jwtService = jwtService;
        this.sessions = sessions;
    }

    /**
     * A token is only accepted if (1) the signature and expiry are valid AND
     * (2) its Session row is still ACTIVE, unexpired and holds the SHA-256 of this token.
     * Logging out (REVOKED) therefore kills a token immediately, even though the JWT itself is unexpired.
     */
    @Transactional(readOnly = true)
    public Optional<AuthenticatedUser> authenticate(String token) {
        Claims claims;
        long userId;
        long sessionId;
        try {
            claims = jwtService.parse(token);
            userId = Long.parseLong(claims.getSubject());
            sessionId = Long.parseLong(claims.getId());
        } catch (JwtException | IllegalArgumentException e) {   // NumberFormatException is an IllegalArgumentException
            return Optional.empty();
        }
        Session s = sessions.findById(sessionId).orElse(null);
        if (s == null
                || s.getStatus() != SessionStatus.ACTIVE
                || !s.getExpiryTime().isAfter(Instant.now())
                || !TokenDigest.matches(token, s.getJwtToken())) {
            return Optional.empty();
        }
        User u = s.getUser();
        if (!u.getUserId().equals(userId)) return Optional.empty();
        return Optional.of(new AuthenticatedUser(u.getUserId(), u.getEmail(), s.getSessionId()));
    }
}
