package com.secureshare.service;

import com.secureshare.crypto.CryptoException;
import com.secureshare.crypto.CryptoService;
import com.secureshare.dto.LoginRequest;
import com.secureshare.dto.LoginResponse;
import com.secureshare.dto.RegisterRequest;
import com.secureshare.exception.ApiException;
import com.secureshare.model.Session;
import com.secureshare.model.SessionStatus;
import com.secureshare.model.User;
import com.secureshare.repository.SessionRepository;
import com.secureshare.repository.UserRepository;
import com.secureshare.security.AuthenticatedUser;
import com.secureshare.security.JwtService;
import com.secureshare.security.TokenDigest;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Note: methods here are intentionally NOT @Transactional as a whole. Each repository call is its own
 * short transaction, so audit rows (e.g. a FAILED login) are committed even when we then throw.
 */
@Service
public class UserService {

    private static final String BAD_CREDENTIALS = "Invalid email or password";

    private final UserRepository users;
    private final SessionRepository sessions;
    private final PasswordEncoder encoder;
    private final CryptoService crypto;
    private final JwtService jwt;
    private final AuditService audit;
    /** Real BCrypt hash used only so an unknown email costs the same as a wrong password. */
    private final String dummyPasswordHash;

    public UserService(UserRepository users, SessionRepository sessions, PasswordEncoder encoder,
                       CryptoService crypto, JwtService jwt, AuditService audit) {
        this.users = users;
        this.sessions = sessions;
        this.encoder = encoder;
        this.crypto = crypto;
        this.jwt = jwt;
        this.audit = audit;
        this.dummyPasswordHash = encoder.encode("timing-equalization-not-a-password");
    }

    private static String normalize(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    public User register(RegisterRequest req, String ip) {
        String email = normalize(req.email());
        PublicKey publicKey = parseAndCheckPublicKey(req.publicKey());

        if (users.existsByEmail(email)) {
            throw ApiException.conflict("An account with this email already exists");
        }
        User u = new User();
        u.setFullName(req.fullName().trim());
        u.setEmail(email);
        u.setPasswordHash(encoder.encode(req.password()));
        u.setPublicKey(crypto.encodePublicKey(publicKey));     // store the canonical encoding
        try {
            u = users.saveAndFlush(u);
        } catch (DataIntegrityViolationException e) {           // lost a race on the UNIQUE(email) constraint
            throw ApiException.conflict("An account with this email already exists");
        }
        audit.log(u.getUserId(), null, "REGISTER", ip, "SUCCESS");
        return u;
    }

    private PublicKey parseAndCheckPublicKey(String encoded) {
        PublicKey key;
        try {
            key = crypto.decodePublicKey(encoded.trim());
        } catch (CryptoException e) {
            throw ApiException.badRequest("publicKey is not a valid Base64 X.509 RSA public key");
        }
        if (!(key instanceof RSAPublicKey rsa) || rsa.getModulus().bitLength() < 2048) {
            throw ApiException.badRequest("publicKey must be an RSA key of at least 2048 bits");
        }
        return key;
    }

    public LoginResponse login(LoginRequest req, String ip) {
        User user = users.findByEmail(normalize(req.email())).orElse(null);
        // Always run BCrypt, including for an unknown email, so the response time does not reveal which it was.
        boolean passwordOk = encoder.matches(req.password(), user == null ? dummyPasswordHash : user.getPasswordHash());
        if (user == null || !passwordOk) {
            audit.log(user == null ? null : user.getUserId(), null, "LOGIN", ip, "FAILURE");
            throw ApiException.unauthorized(BAD_CREDENTIALS);
        }

        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiresAt = now.plusSeconds(jwt.expiryMinutes() * 60);

        // The session id goes into the JWT (jti), so create the row first, then fill in the token.
        Session session = new Session();
        session.setUser(user);
        session.setJwtToken("pending");
        session.setExpiryTime(expiresAt);
        session.setStatus(SessionStatus.ACTIVE);
        session = sessions.saveAndFlush(session);

        String token = jwt.issue(user.getUserId(), session.getSessionId(), now, expiresAt);
        session.setJwtToken(TokenDigest.sha256Hex(token));
        sessions.save(session);

        user.setLastLogin(now);
        users.save(user);

        audit.log(user.getUserId(), null, "LOGIN", ip, "SUCCESS");
        return new LoginResponse(token, "Bearer", expiresAt, user.getUserId(), user.getFullName());
    }

    public void logout(AuthenticatedUser current, String ip) {
        sessions.findById(current.sessionId()).ifPresent(s -> {
            s.setStatus(SessionStatus.REVOKED);
            sessions.save(s);
        });
        audit.log(current.userId(), null, "LOGOUT", ip, "SUCCESS");
    }

    public User getById(Long id) {
        return users.findById(id).orElseThrow(() -> ApiException.notFound("User not found"));
    }

    public User getByEmail(String email) {
        return users.findByEmail(normalize(email)).orElseThrow(() -> ApiException.notFound("User not found"));
    }
}
