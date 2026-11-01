package com.secureshare.crypto;

/** Ciphertext (or IV) was modified: the AES-GCM authentication tag did not verify. */
public class IntegrityException extends CryptoException {
    public IntegrityException(String message, Throwable cause) { super(message, cause); }
}
