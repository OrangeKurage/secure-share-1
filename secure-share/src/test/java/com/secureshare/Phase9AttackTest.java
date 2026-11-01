package com.secureshare;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.secureshare.crypto.CryptoException;
import com.secureshare.crypto.IntegrityException;
import com.secureshare.crypto.PrivateKeyProtector;
import com.secureshare.crypto.SignatureVerificationException;
import com.secureshare.crypto.UnauthorizedRecipientException;
import com.secureshare.model.FileEntity;
import com.secureshare.model.FileShare;
import com.secureshare.model.User;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Phase 9: the recipient's client must fail closed.
 * A tampered blob, a forged signature, a substituted session key, or a sender key that no longer
 * matches the key the recipient pinned are all rejected, and no plaintext is returned.
 */
@SpringBootTest
@AutoConfigureMockMvc
class Phase9AttackTest extends ApiTestSupport {

    static final byte[] PLAIN = "Phase 9 attack target - CONFIDENTIAL. ".repeat(40).getBytes(StandardCharsets.UTF_8);

    @Test
    void untouchedFile_stillDecrypts() throws Exception {
        Client alice = newClient(), bob = newClient();
        long fileId = upload(alice, PLAIN);
        shareWith(alice, fileId, "DOWNLOAD", null, 200, bob);
        assertThat(receive(bob, fileId)).isEqualTo(PLAIN);
    }

    @Test
    void flippedCiphertextBit_isRejectedByGcm_andAudited() throws Exception {
        long fileId = sharedFile();
        flipStoredByte(fileId, 40);
        Client bob = lastBob;
        assertThatThrownBy(() -> receive(bob, fileId)).isInstanceOf(IntegrityException.class);
        postJson(bob, "/files/" + fileId + "/receipt", Map.of("outcome", "FAILURE_INTEGRITY"), 204);
        assertThat(audits.findByUser_UserIdOrderByTimestampDesc(bob.userId()))
                .anyMatch(a -> "VERIFY".equals(a.getAction()) && "FAILURE_INTEGRITY".equals(a.getStatus()));
    }

    @Test
    void flippedIv_isRejectedByGcm() throws Exception {
        long fileId = sharedFile();
        flipStoredByte(fileId, 0);
        assertThatThrownBy(() -> receive(lastBob, fileId)).isInstanceOf(IntegrityException.class);
    }

    @Test
    void flippedAuthenticationTag_isRejectedByGcm() throws Exception {
        long fileId = sharedFile();
        byte[] blob = Files.readAllBytes(blobPath(fileId));
        flipStoredByte(fileId, blob.length - 1);
        assertThatThrownBy(() -> receive(lastBob, fileId)).isInstanceOf(IntegrityException.class);
    }

    @Test
    void truncatedBlob_isRejectedBeforeDecryption() throws Exception {
        long fileId = sharedFile();
        Files.write(blobPath(fileId), new byte[] {1, 2, 3, 4, 5});
        assertThatThrownBy(() -> receive(lastBob, fileId))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("too short");
    }

    @Test
    void forgedSignature_isRejectedAsImpersonation() throws Exception {
        Client alice = newClient(), bob = newClient();
        KeyPair mallory = crypto.generateKeyPair();
        long fileId = upload(alice, PLAIN);
        shareWith(alice, fileId, "DOWNLOAD", null, 200, bob);

        FileEntity f = files.findById(fileId).orElseThrow();
        f.setSignature(crypto.encodeBytes(crypto.signHash(crypto.hashFile(PLAIN), mallory.getPrivate())));
        files.save(f);

        assertThatThrownBy(() -> receive(bob, fileId)).isInstanceOf(SignatureVerificationException.class);
        postJson(bob, "/files/" + fileId + "/receipt", Map.of("outcome", "FAILURE_SIGNATURE"), 204);
    }

    @Test
    void replacedStoredHash_isRejectedEvenWhenTheCiphertextIsIntact() throws Exception {
        long fileId = sharedFile();
        FileEntity f = files.findById(fileId).orElseThrow();
        f.setSha256Hash(crypto.toHex(crypto.hashFile("different file".getBytes(StandardCharsets.UTF_8))));
        files.save(f);
        assertThatThrownBy(() -> receive(lastBob, fileId)).isInstanceOf(IntegrityException.class);
    }

    @Test
    void wrappedKeyForADifferentSessionKey_failsIntegrity() throws Exception {
        long fileId = sharedFile();
        FileShare share = shares.findByFile_FileIdAndRecipient_UserId(fileId, lastBob.userId()).orElseThrow();
        share.setWrappedKey(crypto.encodeBytes(
                crypto.wrapKey(crypto.generateSessionKey(), lastBob.keys().getPublic())));
        shares.save(share);
        assertThatThrownBy(() -> receive(lastBob, fileId)).isInstanceOf(IntegrityException.class);
    }

    @Test
    void garbageWrappedKey_isRejectedAsUnauthorized() throws Exception {
        long fileId = sharedFile();
        FileShare share = shares.findByFile_FileIdAndRecipient_UserId(fileId, lastBob.userId()).orElseThrow();
        byte[] garbage = new byte[256];
        new SecureRandom().nextBytes(garbage);
        share.setWrappedKey(crypto.encodeBytes(garbage));
        shares.save(share);
        assertThatThrownBy(() -> receive(lastBob, fileId)).isInstanceOf(UnauthorizedRecipientException.class);
    }

    @Test
    void swappedDirectoryKey_doesNotMatchTheKeyTheRecipientPinned() throws Exception {
        Client alice = newClient(), bob = newClient();
        long fileId = upload(alice, PLAIN);
        shareWith(alice, fileId, "DOWNLOAD", null, 200, bob);
        String pinned = crypto.fingerprint(alice.keys().getPublic());

        KeyPair mallory = crypto.generateKeyPair();
        User owner = users.findById(alice.userId()).orElseThrow();
        owner.setPublicKey(crypto.encodePublicKey(mallory.getPublic()));
        users.save(owner);
        FileEntity f = files.findById(fileId).orElseThrow();
        f.setSignature(crypto.encodeBytes(crypto.signHash(crypto.hashFile(PLAIN), mallory.getPrivate())));
        files.save(f);

        var bundle = body(getAs(bob, "/files/" + fileId + "/bundle", 200));
        String presented = crypto.fingerprint(crypto.decodePublicKey(bundle.get("ownerPublicKey").asText()));
        assertThat(presented).isNotEqualTo(pinned);
        assertThat(crypto.verifySignature(
                crypto.decodeBytes(bundle.get("signature").asText()),
                crypto.hashFile(PLAIN),
                alice.keys().getPublic())).isFalse();
    }

    @Test
    void privateKeyFile_rejectsWrongPassword_wrongAccount_andTampering() {
        PrivateKeyProtector protector = new PrivateKeyProtector(1_000);
        byte[] secret = "pkcs8-stand-in".getBytes(StandardCharsets.UTF_8);
        char[] password = "correct-horse".toCharArray();
        PrivateKeyProtector.Protected stored = protector.protect(secret, password, "alice@example.com");

        assertThat(protector.unprotect(stored, password, "alice@example.com")).isEqualTo(secret);
        assertThatThrownBy(() -> protector.unprotect(stored, "wrong-password".toCharArray(), "alice@example.com"))
                .isInstanceOf(CryptoException.class);
        assertThatThrownBy(() -> protector.unprotect(stored, password, "bob@example.com"))
                .isInstanceOf(CryptoException.class);

        byte[] ct = Base64.getDecoder().decode(stored.ciphertext());
        ct[0] ^= 0x01;
        PrivateKeyProtector.Protected tampered = new PrivateKeyProtector.Protected(
                stored.kdf(), stored.iterations(), stored.salt(), stored.iv(),
                Base64.getEncoder().encodeToString(ct));
        assertThatThrownBy(() -> protector.unprotect(tampered, password, "alice@example.com"))
                .isInstanceOf(CryptoException.class);
    }

    // ---------------------------------------------------------------- helpers

    private Client lastAlice;
    private Client lastBob;

    private long sharedFile() throws Exception {
        lastAlice = newClient();
        lastBob = newClient();
        long fileId = upload(lastAlice, PLAIN);
        shareWith(lastAlice, fileId, "DOWNLOAD", null, 200, lastBob);
        return fileId;
    }

    private Path blobPath(long fileId) {
        FileEntity f = files.findById(fileId).orElseThrow();
        return Path.of(storagePath).toAbsolutePath().resolve(f.getStoragePath());
    }

    private void flipStoredByte(long fileId, int index) throws Exception {
        Path path = blobPath(fileId);
        byte[] blob = Files.readAllBytes(path);
        blob[index] ^= 0x01;
        Files.write(path, blob);
    }
}
