package com.secureshare.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class CryptoServiceTest {

    static final CryptoService crypto = new CryptoService();
    static KeyPair alice, bob, eve;
    static final byte[] PLAINTEXT = "top secret quarterly report".repeat(1000).getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void keys() {
        alice = crypto.generateKeyPair();
        bob = crypto.generateKeyPair();
        eve = crypto.generateKeyPair();
    }

    @Test
    void roundTrip_encryptWrapUnwrapDecryptVerify() {
        SecretKey session = crypto.generateSessionKey();
        EncryptedPayload p = crypto.encryptFile(PLAINTEXT, session);
        byte[] hash = crypto.hashFile(PLAINTEXT);
        byte[] sig = crypto.signHash(hash, alice.getPrivate());
        byte[] wrappedForBob = crypto.wrapKey(session, bob.getPublic());

        // --- recipient side ---
        SecretKey recovered = crypto.unwrapKey(wrappedForBob, bob.getPrivate());
        byte[] plain = crypto.decryptFile(p.ciphertext(), p.iv(), recovered);
        assertThat(plain).isEqualTo(PLAINTEXT);
        assertThat(crypto.verifySignature(sig, crypto.hashFile(plain), alice.getPublic())).isTrue();
        assertThat(p.ciphertext()).isNotEqualTo(PLAINTEXT);
    }

    @Test
    void multipleRecipients_eachCanUnwrapTheSameKey() {
        SecretKey session = crypto.generateSessionKey();
        byte[] forAlice = crypto.wrapKey(session, alice.getPublic());
        byte[] forBob = crypto.wrapKey(session, bob.getPublic());
        assertThat(crypto.unwrapKey(forAlice, alice.getPrivate()).getEncoded()).isEqualTo(session.getEncoded());
        assertThat(crypto.unwrapKey(forBob, bob.getPrivate()).getEncoded()).isEqualTo(session.getEncoded());
    }

    @Test
    void unauthorizedRecipient_wrongPrivateKeyRejected() {
        byte[] wrappedForBob = crypto.wrapKey(crypto.generateSessionKey(), bob.getPublic());
        assertThatThrownBy(() -> crypto.unwrapKey(wrappedForBob, eve.getPrivate()))
                .isInstanceOf(UnauthorizedRecipientException.class);
    }

    @Test
    void tamperedCiphertext_detectedByGcm() {
        SecretKey session = crypto.generateSessionKey();
        EncryptedPayload p = crypto.encryptFile(PLAINTEXT, session);
        byte[] bad = p.ciphertext().clone();
        bad[10] ^= 0x01;
        assertThatThrownBy(() -> crypto.decryptFile(bad, p.iv(), session))
                .isInstanceOf(IntegrityException.class);
    }

    @Test
    void tamperedTag_detectedByGcm() {
        SecretKey session = crypto.generateSessionKey();
        EncryptedPayload p = crypto.encryptFile(PLAINTEXT, session);
        byte[] bad = p.ciphertext().clone();
        bad[bad.length - 1] ^= 0x01;
        assertThatThrownBy(() -> crypto.decryptFile(bad, p.iv(), session))
                .isInstanceOf(IntegrityException.class);
    }

    @Test
    void impersonation_signatureFromWrongKeyRejected() {
        byte[] hash = crypto.hashFile(PLAINTEXT);
        byte[] forged = crypto.signHash(hash, eve.getPrivate());
        assertThat(crypto.verifySignature(forged, hash, alice.getPublic())).isFalse();
        assertThatThrownBy(() -> crypto.requireValidSignature(forged, hash, alice.getPublic()))
                .isInstanceOf(SignatureVerificationException.class);
    }

    @Test
    void signature_overDifferentContentRejected() {
        byte[] sig = crypto.signHash(crypto.hashFile(PLAINTEXT), alice.getPrivate());
        byte[] otherHash = crypto.hashFile("something else".getBytes(StandardCharsets.UTF_8));
        assertThat(crypto.verifySignature(sig, otherHash, alice.getPublic())).isFalse();
    }

    @Test
    void garbageSignature_returnsFalseNotException() {
        assertThat(crypto.verifySignature(new byte[] {1, 2, 3}, crypto.hashFile(PLAINTEXT), alice.getPublic())).isFalse();
    }

    @Test
    void everyEncryptionUsesAFreshIvAndWrapsDifferently() {
        SecretKey session = crypto.generateSessionKey();
        EncryptedPayload a = crypto.encryptFile(PLAINTEXT, session);
        EncryptedPayload b = crypto.encryptFile(PLAINTEXT, session);
        assertThat(a.iv()).isNotEqualTo(b.iv());
        assertThat(a.ciphertext()).isNotEqualTo(b.ciphertext());
        assertThat(crypto.wrapKey(session, bob.getPublic())).isNotEqualTo(crypto.wrapKey(session, bob.getPublic()));
    }

    @Test
    void sha256_knownVector() {
        String hex = crypto.toHex(crypto.hashFile("abc".getBytes(StandardCharsets.UTF_8)));
        assertThat(hex).isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    @Test
    void blobFormat_roundTrips() {
        EncryptedPayload p = crypto.encryptFile(PLAINTEXT, crypto.generateSessionKey());
        EncryptedPayload back = EncryptedPayload.fromBlob(p.toBlob());
        assertThat(back.iv()).isEqualTo(p.iv());
        assertThat(back.ciphertext()).isEqualTo(p.ciphertext());
    }

    @Test
    void keyEncoding_roundTrips() {
        assertThat(crypto.decodePublicKey(crypto.encodePublicKey(alice.getPublic()))).isEqualTo(alice.getPublic());
        assertThat(crypto.decodePrivateKey(crypto.encodePrivateKey(alice.getPrivate()))).isEqualTo(alice.getPrivate());
    }
}
