package com.secureshare.crypto;

/** Base class for all crypto failures. Unchecked so callers don't drown in try/catch. */
public class CryptoException extends RuntimeException {
    public CryptoException(String message) { super(message); }
    public CryptoException(String message, Throwable cause) { super(message, cause); }
}
