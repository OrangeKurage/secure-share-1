package com.secureshare.cli;

import com.secureshare.crypto.CryptoService;
import java.security.KeyPair;

/**
 * Dev helper until the real CLI exists (Phase 8): run it, copy the PUBLIC key into the register request.
 * The private key is printed once and never sent anywhere. Keep it secret.
 */
public class DevKeyGen {
    public static void main(String[] args) {
        CryptoService crypto = new CryptoService();
        KeyPair kp = crypto.generateKeyPair();
        System.out.println("PUBLIC KEY (send to /users/register):");
        System.out.println(crypto.encodePublicKey(kp.getPublic()));
        System.out.println();
        System.out.println("PRIVATE KEY (keep secret, never upload):");
        System.out.println(crypto.encodePrivateKey(kp.getPrivate()));
    }
}
