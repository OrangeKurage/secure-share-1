package com.secureshare.crypto;

/** The session key could not be unwrapped with the supplied private key: not an intended recipient. */
public class UnauthorizedRecipientException extends CryptoException {
    public UnauthorizedRecipientException(String message, Throwable cause) { super(message, cause); }
}
