package com.secureshare.crypto;

/** The digital signature does not match the claimed sender: file is untrusted. */
public class SignatureVerificationException extends CryptoException {
    public SignatureVerificationException(String message) { super(message); }
}
