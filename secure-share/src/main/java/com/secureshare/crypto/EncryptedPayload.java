package com.secureshare.crypto;

import java.util.Arrays;

/**
 * Result of encrypting a file with AES-256-GCM.
 * {@code ciphertext} already includes the 16-byte GCM authentication tag at the end.
 */
public record EncryptedPayload(byte[] iv, byte[] ciphertext) {

    public static final int IV_LENGTH = 12;

    /** On-disk / on-wire format: IV (12 bytes) || ciphertext || tag. */
    public byte[] toBlob() {
        byte[] blob = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, blob, 0, iv.length);
        System.arraycopy(ciphertext, 0, blob, iv.length, ciphertext.length);
        return blob;
    }

    public static EncryptedPayload fromBlob(byte[] blob) {
        if (blob == null || blob.length < IV_LENGTH + 16) {
            throw new CryptoException("Encrypted blob is too short to be valid");
        }
        return new EncryptedPayload(
                Arrays.copyOfRange(blob, 0, IV_LENGTH),
                Arrays.copyOfRange(blob, IV_LENGTH, blob.length));
    }
}
