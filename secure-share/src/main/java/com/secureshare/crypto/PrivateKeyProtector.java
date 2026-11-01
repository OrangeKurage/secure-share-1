package com.secureshare.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Protects a private key at rest (SRS 6.3): AES-256-GCM under a key derived from the user's password
 * with PBKDF2-HMAC-SHA256. The "context" (the account email) is bound in as GCM associated data, so a key file
 * cannot be silently swapped between accounts. A wrong password or any modification fails the GCM tag.
 */
public class PrivateKeyProtector {

    public static final int DEFAULT_ITERATIONS = 600_000;       // OWASP guidance for PBKDF2-HMAC-SHA256
    private static final String KDF = "PBKDF2WithHmacSHA256";

    /** Everything needed to decrypt later, except the password. All binary values are Base64. */
    public record Protected(String kdf, int iterations, String salt, String iv, String ciphertext) {}

    private final int iterations;
    private final SecureRandom random = new SecureRandom();

    /** Iterations can be lowered for tests with -Dsecureshare.kdf.iterations=1000. Never do that in real use. */
    public PrivateKeyProtector() {
        this(Integer.getInteger("secureshare.kdf.iterations", DEFAULT_ITERATIONS));
    }

    public PrivateKeyProtector(int iterations) {
        if (iterations < 1) throw new IllegalArgumentException("iterations must be positive");
        this.iterations = iterations;
    }

    public Protected protect(byte[] secret, char[] password, String context) {
        try {
            byte[] salt = new byte[16];
            byte[] iv = new byte[12];
            random.nextBytes(salt);
            random.nextBytes(iv);
            SecretKey key = derive(password, salt, iterations);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            c.updateAAD(context.getBytes(StandardCharsets.UTF_8));
            byte[] ct = c.doFinal(secret);
            Base64.Encoder b64 = Base64.getEncoder();
            return new Protected(KDF, iterations, b64.encodeToString(salt), b64.encodeToString(iv), b64.encodeToString(ct));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Could not protect the private key", e);
        }
    }

    /** @throws CryptoException "Wrong password..." if the password is wrong or the file was modified. */
    public byte[] unprotect(Protected p, char[] password, String context) {
        if (!KDF.equals(p.kdf()) || p.iterations() < 1 || p.iterations() > 50_000_000) {
            throw new CryptoException("Unsupported key file format");
        }
        try {
            Base64.Decoder b64 = Base64.getDecoder();
            SecretKey key = derive(password, b64.decode(p.salt()), p.iterations());
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, b64.decode(p.iv())));
            c.updateAAD(context.getBytes(StandardCharsets.UTF_8));
            return c.doFinal(b64.decode(p.ciphertext()));
        } catch (javax.crypto.AEADBadTagException e) {
            throw new CryptoException("Wrong password, or the key file was modified", e);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new CryptoException("Key file is corrupted", e);
        }
    }

    private static SecretKey derive(char[] password, byte[] salt, int iterations) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256);
        try {
            byte[] raw = SecretKeyFactory.getInstance(KDF).generateSecret(spec).getEncoded();
            return new SecretKeySpec(raw, "AES");
        } finally {
            spec.clearPassword();
        }
    }
}
