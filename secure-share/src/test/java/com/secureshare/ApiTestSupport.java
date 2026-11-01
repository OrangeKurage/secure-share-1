package com.secureshare;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.secureshare.crypto.CryptoService;
import com.secureshare.crypto.EncryptedPayload;
import com.secureshare.repository.AuditLogRepository;
import com.secureshare.repository.FileRepository;
import com.secureshare.repository.FileShareRepository;
import com.secureshare.repository.SessionRepository;
import com.secureshare.repository.UserRepository;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Shared "client" logic for integration tests. Everything cryptographic here is what the real CLI does
 * on the user's machine: the server under test only ever sees ciphertext, wrapped keys, hashes, signatures.
 */
abstract class ApiTestSupport {

    @Autowired protected MockMvc mvc;
    @Autowired protected ObjectMapper json;
    @Autowired protected CryptoService crypto;
    @Autowired protected UserRepository users;
    @Autowired protected FileRepository files;
    @Autowired protected FileShareRepository shares;
    @Autowired protected SessionRepository sessions;
    @Autowired protected AuditLogRepository audits;
    @Value("${app.storage.path}") protected String storagePath;

    protected static final String PASSWORD = "SecurePass123";

    protected record Client(String email, long userId, KeyPair keys, String token) {}

    protected Client newClient() throws Exception {
        KeyPair kp = crypto.generateKeyPair();
        String email = "user-" + UUID.randomUUID() + "@example.com";
        MvcResult reg = mvc.perform(post("/users/register").contentType(APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("fullName", "Test User", "email", email,
                                "password", PASSWORD, "publicKey", crypto.encodePublicKey(kp.getPublic())))))
                .andExpect(status().isCreated()).andReturn();
        long id = body(reg).get("userId").asLong();
        MvcResult login = mvc.perform(post("/users/login").contentType(APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("email", email, "password", PASSWORD))))
                .andExpect(status().isOk()).andReturn();
        return new Client(email, id, kp, body(login).get("token").asText());
    }

    protected JsonNode body(MvcResult r) throws Exception {
        return json.readTree(r.getResponse().getContentAsString());
    }

    protected MvcResult getAs(Client c, String url, int expected) throws Exception {
        return mvc.perform(get(url).header("Authorization", "Bearer " + c.token()))
                .andExpect(status().is(expected)).andReturn();
    }

    protected MvcResult postJson(Client c, String url, Object payload, int expected) throws Exception {
        return mvc.perform(post(url).header("Authorization", "Bearer " + c.token())
                        .contentType(APPLICATION_JSON).content(json.writeValueAsString(payload)))
                .andExpect(status().is(expected)).andReturn();
    }

    /** Client-side: encrypt, hash, sign, wrap for self, upload. Returns the new file id. */
    protected long upload(Client c, byte[] plain) throws Exception {
        SecretKey session = crypto.generateSessionKey();
        EncryptedPayload p = crypto.encryptFile(plain, session);
        byte[] hash = crypto.hashFile(plain);
        MvcResult r = mvc.perform(multipart("/files/upload")
                        .file(new MockMultipartFile("file", "report.pdf.enc", "application/octet-stream", p.toBlob()))
                        .param("fileName", "report.pdf")
                        .param("sha256Hash", crypto.toHex(hash))
                        .param("signature", crypto.encodeBytes(crypto.signHash(hash, c.keys().getPrivate())))
                        .param("encryptedAesKey", crypto.encodeBytes(crypto.wrapKey(session, c.keys().getPublic())))
                        .header("Authorization", "Bearer " + c.token()))
                .andExpect(status().isCreated()).andReturn();
        return body(r).get("fileId").asLong();
    }

    /** Owner's client: fetch own wrapped key, unwrap it, re-wrap for each recipient, POST the share. */
    protected MvcResult shareWith(Client owner, long fileId, String permission, Instant expires,
                                  int expectedStatus, Client... recipients) throws Exception {
        JsonNode bundle = body(getAs(owner, "/files/" + fileId + "/bundle", 200));
        SecretKey session = crypto.unwrapKey(crypto.decodeBytes(bundle.get("wrappedKey").asText()),
                owner.keys().getPrivate());
        List<Map<String, String>> list = new ArrayList<>();
        for (Client r : recipients) {
            list.add(Map.of("email", r.email(),
                    "wrappedKey", crypto.encodeBytes(crypto.wrapKey(session, r.keys().getPublic()))));
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("recipients", list);
        if (permission != null) payload.put("permission", permission);
        if (expires != null) payload.put("expiresAt", expires.toString());
        return postJson(owner, "/files/" + fileId + "/share", payload, expectedStatus);
    }

    /**
     * Recipient's client: bundle -> download -> unwrap -> decrypt (GCM) -> verify hash + signature -> receipt.
     * Throws a CryptoException subclass if anything is wrong (fail closed: no plaintext is returned).
     */
    protected byte[] receive(Client c, long fileId) throws Exception {
        JsonNode b = body(getAs(c, "/files/" + fileId + "/bundle", 200));
        byte[] blob = getAs(c, "/files/" + fileId + "/download", 200).getResponse().getContentAsByteArray();
        EncryptedPayload p = EncryptedPayload.fromBlob(blob);
        SecretKey key = crypto.unwrapKey(crypto.decodeBytes(b.get("wrappedKey").asText()), c.keys().getPrivate());
        byte[] plain = crypto.decryptFile(p.ciphertext(), p.iv(), key);
        byte[] hash = crypto.hashFile(plain);
        PublicKey senderKey = crypto.decodePublicKey(b.get("ownerPublicKey").asText());
        crypto.requireValidSignature(crypto.decodeBytes(b.get("signature").asText()), hash, senderKey);
        if (!crypto.toHex(hash).equals(b.get("sha256Hash").asText())) {
            throw new com.secureshare.crypto.IntegrityException("Hash mismatch", null);
        }
        postJson(c, "/files/" + fileId + "/receipt", Map.of("outcome", "SUCCESS"), 204);
        return plain;
    }
}
