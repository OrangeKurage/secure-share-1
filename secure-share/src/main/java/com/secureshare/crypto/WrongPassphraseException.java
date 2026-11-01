package com.secureshare.crypto;

/** The passphrase did not decrypt the protected data (or the data was altered). */
public class WrongPassphraseException extends CryptoException {
    public WrongPassphraseException(String message, Throwable cause) { super(message, cause); }
}
