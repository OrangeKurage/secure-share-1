package com.secureshare.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Password-based encryption for data at rest (the client's private-key file).
 * PBKDF2-HMAC-SHA256 (high iteration count, random salt) derives an AES-256 key; AES-GCM encrypts and
 * authenticates. The AAD binds the ciphertext to its context (e.g. the account e-mail).
 */
public class PassphraseCrypto {

    public static final int DEFAULT_ITERATIONS = 310_000;     // OWASP guidance for PBKDF2-HMAC-SHA256
    private static final int MIN_ITERATIONS = 100_000;        // refuse files downgraded to a weak KDF
    private static final int MAX_ITERATIONS = 10_000_000;     // refuse files that would hang us

    public record Sealed(int iterations, byte[] salt, byte[] iv, byte[] ciphertext) {}

    private final SecureRandom random = new SecureRandom();

    public Sealed seal(byte[] plaintext, char[] passphrase, byte[] aad) {
        byte[] salt = new byte[16];
        byte[] iv = new byte[12];
        random.nextBytes(salt);
        random.nextBytes(iv);
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, derive(passphrase, salt, DEFAULT_ITERATIONS), new GCMParameterSpec(128, iv));
            c.updateAAD(aad);
            return new Sealed(DEFAULT_ITERATIONS, salt, iv, c.doFinal(plaintext));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Passphrase encryption failed", e);
        }
    }

    /** @throws WrongPassphraseException for a wrong passphrase OR any modification of the sealed data. */
    public byte[] open(Sealed sealed, char[] passphrase, byte[] aad) {
        if (sealed.iterations() < MIN_ITERATIONS || sealed.iterations() > MAX_ITERATIONS) {
            throw new CryptoException("Key file has unacceptable KDF settings");
        }
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, derive(passphrase, sealed.salt(), sealed.iterations()),
                    new GCMParameterSpec(128, sealed.iv()));
            c.updateAAD(aad);
            return c.doFinal(sealed.ciphertext());
        } catch (AEADBadTagException e) {
            throw new WrongPassphraseException("Wrong key passphrase (or the key file was modified)", e);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Passphrase decryption failed", e);
        }
    }

    private static SecretKey derive(char[] passphrase, byte[] salt, int iterations) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(passphrase, salt, iterations, 256);
        try {
            byte[] raw = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            return new SecretKeySpec(raw, "AES");
        } finally {
            spec.clearPassword();
        }
    }
}
