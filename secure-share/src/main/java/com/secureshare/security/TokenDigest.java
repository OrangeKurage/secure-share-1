package com.secureshare.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** SHA-256 of a JWT, so the sessions table never holds a usable bearer token. */
public final class TokenDigest {

    private TokenDigest() {}

    public static String sha256Hex(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static boolean matches(String token, String storedHex) {
        if (token == null || storedHex == null) return false;
        byte[] actual = sha256Hex(token).getBytes(StandardCharsets.US_ASCII);
        byte[] expected = storedHex.getBytes(StandardCharsets.US_ASCII);
        return MessageDigest.isEqual(actual, expected);
    }
}
