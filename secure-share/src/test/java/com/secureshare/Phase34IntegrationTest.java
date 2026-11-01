package com.secureshare;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.secureshare.crypto.CryptoService;
import com.secureshare.crypto.EncryptedPayload;
import com.secureshare.model.AuditLog;
import com.secureshare.model.FileEntity;
import com.secureshare.model.Session;
import com.secureshare.model.User;
import com.secureshare.repository.AuditLogRepository;
import com.secureshare.repository.FileRepository;
import com.secureshare.repository.SessionRepository;
import com.secureshare.repository.UserRepository;
import com.secureshare.security.TokenDigest;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Preliminary end-to-end check of Phase 3 (auth) and Phase 4 (zero-trust upload).
 * The "client" side (key generation, encryption, hashing, signing, wrapping) is done in the test
 * with CryptoService, exactly as the real CLI will do it.
 */
@SpringBootTest
@AutoConfigureMockMvc
class Phase34IntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired CryptoService crypto;
    @Autowired UserRepository users;
    @Autowired FileRepository files;
    @Autowired SessionRepository sessions;
    @Autowired AuditLogRepository audits;
    @Value("${app.storage.path}") String storagePath;

    static final String PASSWORD = "SecurePass123";

    // ------------------------------------------------------------ helpers

    private static String uniqueEmail() {
        return "user-" + UUID.randomUUID() + "@example.com";
    }

    private String registerBody(String email, String password, String publicKey) throws Exception {
        return json.writeValueAsString(Map.of(
                "fullName", "Test User", "email", email, "password", password, "publicKey", publicKey));
    }

    private long register(String email, KeyPair kp) throws Exception {
        MvcResult r = mvc.perform(post("/users/register").contentType(APPLICATION_JSON)
                        .content(registerBody(email, PASSWORD, crypto.encodePublicKey(kp.getPublic()))))
                .andExpect(status().isCreated()).andReturn();
        return json.readTree(r.getResponse().getContentAsString()).get("userId").asLong();
    }

    private String login(String email, String password) throws Exception {
        MvcResult r = mvc.perform(post("/users/login").contentType(APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("email", email, "password", password))))
                .andExpect(status().isOk()).andReturn();
        return json.readTree(r.getResponse().getContentAsString()).get("token").asText();
    }

    /** Everything the CLI will do on the client before uploading. */
    private record Prepared(byte[] plain, byte[] blob, String hashHex, String sigB64, String wrappedB64) {}

    private Prepared prepare(byte[] plain, KeyPair uploader, KeyPair signer) {
        SecretKey session = crypto.generateSessionKey();
        EncryptedPayload p = crypto.encryptFile(plain, session);
        byte[] hash = crypto.hashFile(plain);
        byte[] sig = crypto.signHash(hash, signer.getPrivate());
        byte[] wrapped = crypto.wrapKey(session, uploader.getPublic());
        return new Prepared(plain, p.toBlob(), crypto.toHex(hash), crypto.encodeBytes(sig), crypto.encodeBytes(wrapped));
    }

    private MvcResult upload(String token, Prepared p, int expectedStatus) throws Exception {
        var req = multipart("/files/upload")
                .file(new MockMultipartFile("file", "payroll.pdf.enc", "application/octet-stream", p.blob()))
                .param("fileName", "payroll.pdf")
                .param("sha256Hash", p.hashHex())
                .param("signature", p.sigB64())
                .param("encryptedAesKey", p.wrappedB64());
        if (token != null) req.header("Authorization", "Bearer " + token);
        return mvc.perform(req).andExpect(status().is(expectedStatus)).andReturn();
    }

    // ------------------------------------------------- Phase 3: registration

    @Test
    void register_succeeds_andNeverExposesPasswordOrPrivateKey() throws Exception {
        KeyPair kp = crypto.generateKeyPair();
        String email = uniqueEmail();
        MvcResult r = mvc.perform(post("/users/register").contentType(APPLICATION_JSON)
                        .content(registerBody(email, PASSWORD, crypto.encodePublicKey(kp.getPublic()))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.passwordHash").doesNotExist())
                .andReturn();
        assertThat(r.getResponse().getContentAsString()).doesNotContain(crypto.encodePrivateKey(kp.getPrivate()));

        User stored = users.findByEmail(email).orElseThrow();
        assertThat(stored.getPasswordHash()).startsWith("$2");          // BCrypt, not plaintext
        assertThat(stored.getPasswordHash()).doesNotContain(PASSWORD);
        assertThat(stored.getPublicKey()).isEqualTo(crypto.encodePublicKey(kp.getPublic()));
    }

    @Test
    void register_duplicateEmail_isRejectedWith409() throws Exception {
        String email = uniqueEmail();
        register(email, crypto.generateKeyPair());
        mvc.perform(post("/users/register").contentType(APPLICATION_JSON)
                        .content(registerBody(email, PASSWORD, crypto.encodePublicKey(crypto.generateKeyPair().getPublic()))))
                .andExpect(status().isConflict());
    }

    @Test
    void register_rejectsBadInput() throws Exception {
        String goodKey = crypto.encodePublicKey(crypto.generateKeyPair().getPublic());
        // short password
        mvc.perform(post("/users/register").contentType(APPLICATION_JSON)
                .content(registerBody(uniqueEmail(), "short", goodKey))).andExpect(status().isBadRequest());
        // not a key
        mvc.perform(post("/users/register").contentType(APPLICATION_JSON)
                .content(registerBody(uniqueEmail(), PASSWORD, "bm90LWEta2V5"))).andExpect(status().isBadRequest());
        // 1024-bit RSA key is too weak
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(1024);
        mvc.perform(post("/users/register").contentType(APPLICATION_JSON)
                .content(registerBody(uniqueEmail(), PASSWORD, crypto.encodePublicKey(g.generateKeyPair().getPublic()))))
                .andExpect(status().isBadRequest());
    }

    // ------------------------------------------------------ Phase 3: login

    @Test
    void login_wrongPasswordAndUnknownEmail_bothGetSame401() throws Exception {
        String email = uniqueEmail();
        register(email, crypto.generateKeyPair());
        mvc.perform(post("/users/login").contentType(APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("email", email, "password", "WrongPassword1"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid email or password"));
        mvc.perform(post("/users/login").contentType(APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("email", uniqueEmail(), "password", PASSWORD))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid email or password"));
    }

    @Test
    void login_success_tokenWorks_lastLoginSet_auditWritten() throws Exception {
        String email = uniqueEmail();
        long userId = register(email, crypto.generateKeyPair());
        String token = login(email, PASSWORD);

        mvc.perform(get("/users/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email));

        assertThat(users.findById(userId).orElseThrow().getLastLogin()).isNotNull();
        List<AuditLog> log = audits.findByUser_UserIdOrderByTimestampDesc(userId);
        assertThat(log).anyMatch(a -> a.getAction().equals("LOGIN") && "SUCCESS".equals(a.getStatus()));
    }

    @Test
    void failedLogin_isAudited() throws Exception {
        String email = uniqueEmail();
        long userId = register(email, crypto.generateKeyPair());
        mvc.perform(post("/users/login").contentType(APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("email", email, "password", "WrongPassword1"))))
                .andExpect(status().isUnauthorized());
        assertThat(audits.findByUser_UserIdOrderByTimestampDesc(userId))
                .anyMatch(a -> a.getAction().equals("LOGIN") && "FAILURE".equals(a.getStatus()));
    }

    // ------------------------------------------- Phase 3: protected routes

    @Test
    void protectedRoutes_rejectMissingAndGarbageTokens() throws Exception {
        mvc.perform(get("/users/me")).andExpect(status().isUnauthorized());
        mvc.perform(get("/users/me").header("Authorization", "Bearer not.a.jwt")).andExpect(status().isUnauthorized());
        mvc.perform(get("/files/mine")).andExpect(status().isUnauthorized());
    }

    @Test
    void tamperedToken_isRejected() throws Exception {
        String email = uniqueEmail();
        register(email, crypto.generateKeyPair());
        String token = login(email, PASSWORD);
        String forged = token.substring(0, token.length() - 3) + (token.endsWith("AAA") ? "BBB" : "AAA");
        mvc.perform(get("/users/me").header("Authorization", "Bearer " + forged)).andExpect(status().isUnauthorized());
    }

    @Test
    void logout_revokesTokenImmediately_replayRejected() throws Exception {
        String email = uniqueEmail();
        register(email, crypto.generateKeyPair());
        String token = login(email, PASSWORD);
        mvc.perform(get("/users/me").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        mvc.perform(post("/users/logout").header("Authorization", "Bearer " + token)).andExpect(status().isNoContent());
        mvc.perform(get("/users/me").header("Authorization", "Bearer " + token)).andExpect(status().isUnauthorized());
    }

    @Test
    void expiredSession_isRejected() throws Exception {
        String email = uniqueEmail();
        register(email, crypto.generateKeyPair());
        String token = login(email, PASSWORD);
        Session s = sessions.findAll().stream()
                .filter(x -> TokenDigest.sha256Hex(token).equals(x.getJwtToken())).findFirst().orElseThrow();
        assertThat(s.getJwtToken()).doesNotContain(token);
        s.setExpiryTime(Instant.now().minusSeconds(5));
        sessions.save(s);
        mvc.perform(get("/users/me").header("Authorization", "Bearer " + token)).andExpect(status().isUnauthorized());
    }

    @Test
    void publicKeyDirectory_lookupByEmailAndId() throws Exception {
        KeyPair bob = crypto.generateKeyPair();
        String bobEmail = uniqueEmail();
        long bobId = register(bobEmail, bob);
        String aliceEmail = uniqueEmail();
        register(aliceEmail, crypto.generateKeyPair());
        String token = login(aliceEmail, PASSWORD);

        mvc.perform(get("/users/lookup").param("email", bobEmail).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.publicKey").value(crypto.encodePublicKey(bob.getPublic())));
        mvc.perform(get("/users/" + bobId + "/public-key").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        mvc.perform(get("/users/lookup").param("email", "nobody@example.com").header("Authorization", "Bearer " + token))
                .andExpect(status().isNotFound());
        mvc.perform(get("/users/lookup").param("email", bobEmail)).andExpect(status().isUnauthorized());
    }

    // -------------------------------------------------- Phase 4: upload

    @Test
    void upload_endToEnd_serverStoresOnlyCiphertext_andClientCanRecoverEverything() throws Exception {
        KeyPair kp = crypto.generateKeyPair();
        String email = uniqueEmail();
        long userId = register(email, kp);
        String token = login(email, PASSWORD);

        byte[] plain = "CONFIDENTIAL payroll data - do not leak. ".repeat(500).getBytes(StandardCharsets.UTF_8);
        Prepared p = prepare(plain, kp, kp);

        MvcResult r = upload(token, p, 201);
        long fileId = json.readTree(r.getResponse().getContentAsString()).get("fileId").asLong();

        // 1. metadata row is complete and correct
        FileEntity f = files.findById(fileId).orElseThrow();
        assertThat(f.getFileName()).isEqualTo("payroll.pdf");
        assertThat(f.getFileType()).isEqualTo("pdf");
        assertThat(f.getFileSize()).isEqualTo(plain.length);
        assertThat(f.getSha256Hash()).isEqualTo(p.hashHex());
        assertThat(f.getSignature()).isEqualTo(p.sigB64());
        assertThat(f.getEncryptedAesKey()).isEqualTo(p.wrappedB64());
        assertThat(f.getUploadDate()).isNotNull();

        // 2. the blob on disk is the ciphertext, NOT the plaintext
        byte[] stored = Files.readAllBytes(Path.of(storagePath).toAbsolutePath().resolve(f.getStoragePath()));
        assertThat(stored).isEqualTo(p.blob());
        assertThat(stored).isNotEqualTo(plain);
        assertThat(new String(stored, StandardCharsets.ISO_8859_1)).doesNotContain("CONFIDENTIAL");

        // 3. the owner can decrypt what the server stored and the signature verifies
        EncryptedPayload sp = EncryptedPayload.fromBlob(stored);
        SecretKey key = crypto.unwrapKey(crypto.decodeBytes(f.getEncryptedAesKey()), kp.getPrivate());
        byte[] recovered = crypto.decryptFile(sp.ciphertext(), sp.iv(), key);
        assertThat(recovered).isEqualTo(plain);
        assertThat(crypto.verifySignature(crypto.decodeBytes(f.getSignature()), crypto.hashFile(recovered), kp.getPublic())).isTrue();

        // 4. listed under "my files" and audited
        mvc.perform(get("/files/mine").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk()).andExpect(jsonPath("$[0].fileId").value(fileId));
        assertThat(audits.findByUser_UserIdOrderByTimestampDesc(userId))
                .anyMatch(a -> a.getAction().equals("UPLOAD") && "SUCCESS".equals(a.getStatus()));
    }

    @Test
    void upload_withoutToken_is401() throws Exception {
        KeyPair kp = crypto.generateKeyPair();
        upload(null, prepare("x".getBytes(StandardCharsets.UTF_8), kp, kp), 401);
    }

    @Test
    void upload_signatureFromSomeoneElse_isRejected_nothingStored_failureAudited() throws Exception {
        KeyPair alice = crypto.generateKeyPair();
        KeyPair mallory = crypto.generateKeyPair();
        String email = uniqueEmail();
        long userId = register(email, alice);
        String token = login(email, PASSWORD);

        Prepared forged = prepare("hello".getBytes(StandardCharsets.UTF_8), alice, mallory);   // signed with the wrong key
        upload(token, forged, 422);

        assertThat(files.findByOwner_UserId(userId)).isEmpty();
        assertThat(audits.findByUser_UserIdOrderByTimestampDesc(userId))
                .anyMatch(a -> a.getAction().equals("UPLOAD") && "FAILURE".equals(a.getStatus()));
    }

    @Test
    void upload_malformedFields_areRejectedWith400() throws Exception {
        KeyPair kp = crypto.generateKeyPair();
        String email = uniqueEmail();
        register(email, kp);
        String token = login(email, PASSWORD);
        Prepared ok = prepare("hello".getBytes(StandardCharsets.UTF_8), kp, kp);

        upload(token, new Prepared(ok.plain(), new byte[5], ok.hashHex(), ok.sigB64(), ok.wrappedB64()), 400);     // blob too short
        upload(token, new Prepared(ok.plain(), ok.blob(), "zz", ok.sigB64(), ok.wrappedB64()), 400);               // bad hash
        upload(token, new Prepared(ok.plain(), ok.blob(), ok.hashHex(), "AAAA", ok.wrappedB64()), 400);            // bad signature length
        upload(token, new Prepared(ok.plain(), ok.blob(), ok.hashHex(), ok.sigB64(), "AAAA"), 400);                // bad wrapped key length
    }

    @Test
    void upload_pathTraversalInFileName_isNeutralised() throws Exception {
        KeyPair kp = crypto.generateKeyPair();
        String email = uniqueEmail();
        register(email, kp);
        String token = login(email, PASSWORD);
        Prepared p = prepare("hello".getBytes(StandardCharsets.UTF_8), kp, kp);
        MvcResult r = mvc.perform(multipart("/files/upload")
                        .file(new MockMultipartFile("file", "x.enc", "application/octet-stream", p.blob()))
                        .param("fileName", "../../etc/passwd")
                        .param("sha256Hash", p.hashHex()).param("signature", p.sigB64())
                        .param("encryptedAesKey", p.wrappedB64())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isCreated()).andReturn();
        assertThat(json.readTree(r.getResponse().getContentAsString()).get("fileName").asText()).doesNotContain("/");
    }
}
