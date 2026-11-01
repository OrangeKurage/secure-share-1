package com.secureshare.crypto;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

/**
 * All cryptographic operations for the platform. Pure Java (no Spring) so the server,
 * the tests and the CLI client can all share exactly the same code.
 *
 *  - Bulk encryption : AES-256-GCM, fresh random 96-bit IV per file
 *  - Key wrapping    : RSA-2048 OAEP, SHA-256 for BOTH the hash and MGF1 (never PKCS#1 v1.5)
 *  - Hashing         : SHA-256
 *  - Signatures      : RSASSA-PSS, SHA-256, MGF1-SHA-256, 32-byte salt
 */
public class CryptoService {

    private static final int RSA_BITS = 2048;
    private static final int AES_BITS = 256;
    private static final int GCM_TAG_BITS = 128;

    private final SecureRandom random = new SecureRandom();

    // ---------------------------------------------------------------- keys

    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(RSA_BITS, random);
            return g.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("RSA key generation failed", e);
        }
    }

    public SecretKey generateSessionKey() {
        try {
            KeyGenerator g = KeyGenerator.getInstance("AES");
            g.init(AES_BITS, random);
            return g.generateKey();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("AES key generation failed", e);
        }
    }

    // ---------------------------------------------------------- AES-256-GCM

    public EncryptedPayload encryptFile(byte[] plaintext, SecretKey sessionKey) {
        try {
            byte[] iv = new byte[EncryptedPayload.IV_LENGTH];
            random.nextBytes(iv);                       // new IV for every call: never reused
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, sessionKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            return new EncryptedPayload(iv, c.doFinal(plaintext));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("File encryption failed", e);
        }
    }

    /** @throws IntegrityException if the ciphertext, IV or key is wrong/modified (fail closed). */
    public byte[] decryptFile(byte[] ciphertext, byte[] iv, SecretKey sessionKey) {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, sessionKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            return c.doFinal(ciphertext);
        } catch (AEADBadTagException e) {
            throw new IntegrityException("Integrity check failed: file was modified or corrupted", e);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("File decryption failed", e);
        }
    }

    // ------------------------------------------------------------ RSA-OAEP

    private static OAEPParameterSpec oaep() {
        // The JDK's "OAEPWithSHA-256AndMGF1Padding" silently uses SHA-1 inside MGF1.
        // Passing the parameters explicitly makes it SHA-256 everywhere.
        return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    }

    public byte[] wrapKey(SecretKey sessionKey, PublicKey recipientPublicKey) {
        try {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
            c.init(Cipher.ENCRYPT_MODE, recipientPublicKey, oaep(), random);
            return c.doFinal(sessionKey.getEncoded());
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Key wrapping failed", e);
        }
    }

    /** @throws UnauthorizedRecipientException if this private key is not the intended recipient's. */
    public SecretKey unwrapKey(byte[] wrappedKey, PrivateKey recipientPrivateKey) {
        try {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
            c.init(Cipher.DECRYPT_MODE, recipientPrivateKey, oaep());
            byte[] raw = c.doFinal(wrappedKey);
            if (raw.length != AES_BITS / 8) {
                throw new UnauthorizedRecipientException("Unwrapped key has unexpected length", null);
            }
            return new SecretKeySpec(raw, "AES");
        } catch (GeneralSecurityException e) {
            throw new UnauthorizedRecipientException("You are not an authorized recipient of this file", e);
        }
    }

    // ------------------------------------------------- SHA-256 & signatures

    public byte[] hashFile(byte[] plaintext) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(plaintext);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("SHA-256 unavailable", e);
        }
    }

    public String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** Parses a 64-char hex string (e.g. a SHA-256 digest) back to bytes. */
    public byte[] fromHex(String hex) {
        if (hex == null || hex.length() % 2 != 0) throw new CryptoException("Invalid hex string");
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(2 * i), 16), lo = Character.digit(hex.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) throw new CryptoException("Invalid hex string");
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static PSSParameterSpec pss() {
        return new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    }

    public byte[] signHash(byte[] fileHash, PrivateKey senderPrivateKey) {
        try {
            Signature s = Signature.getInstance("RSASSA-PSS");
            s.setParameter(pss());
            s.initSign(senderPrivateKey, random);
            s.update(fileHash);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Signing failed", e);
        }
    }

    /** Returns false (never throws) for a bad signature, so callers can decide how to react. */
    public boolean verifySignature(byte[] signature, byte[] fileHash, PublicKey senderPublicKey) {
        try {
            Signature s = Signature.getInstance("RSASSA-PSS");
            s.setParameter(pss());
            s.initVerify(senderPublicKey);
            s.update(fileHash);
            return s.verify(signature);
        } catch (SignatureException e) {
            return false;                 // malformed signature bytes = invalid
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Signature verification failed to run", e);
        }
    }

    /** Fail-closed variant: throws instead of returning false. */
    public void requireValidSignature(byte[] signature, byte[] fileHash, PublicKey senderPublicKey) {
        if (!verifySignature(signature, fileHash, senderPublicKey)) {
            throw new SignatureVerificationException("Signature does not match the claimed sender: file is untrusted");
        }
    }

    /**
     * Short human-comparable fingerprint of a public key (first 16 bytes of SHA-256, colon separated).
     * Users can compare these out-of-band to be sure the server did not swap a key (there is no CA).
     */
    public String fingerprint(PublicKey key) {
        byte[] h = hashFile(key.getEncoded());
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", h[i]));
        }
        return sb.toString();
    }

    // ------------------------------------------------ key (de)serialisation

    public String encodePublicKey(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());          // X.509 SubjectPublicKeyInfo
    }

    public PublicKey decodePublicKey(String base64) {
        try {
            return KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64)));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new CryptoException("Invalid public key", e);
        }
    }

    public String encodePrivateKey(PrivateKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());          // PKCS#8
    }

    public PrivateKey decodePrivateKey(String base64) {
        try {
            return KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64)));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new CryptoException("Invalid private key", e);
        }
    }

    public String encodeBytes(byte[] data) { return Base64.getEncoder().encodeToString(data); }

    public byte[] decodeBytes(String base64) {
        try { return Base64.getDecoder().decode(base64.getBytes(StandardCharsets.US_ASCII)); }
        catch (IllegalArgumentException e) { throw new CryptoException("Invalid Base64 data", e); }
    }
}
