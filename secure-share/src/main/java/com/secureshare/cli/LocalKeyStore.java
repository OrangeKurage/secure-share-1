package com.secureshare.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.secureshare.crypto.CryptoException;
import com.secureshare.crypto.CryptoService;
import com.secureshare.crypto.PassphraseCrypto;
import com.secureshare.crypto.WrongPassphraseException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;

/**
 * The user's private key never leaves this machine and is never stored in plaintext:
 * it is encrypted with a key derived from a passphrase (PBKDF2 + AES-256-GCM, see PassphraseCrypto).
 */
public final class LocalKeyStore {

    public record Loaded(PrivateKey privateKey, PublicKey publicKey) {}

    private final CliConfig config;
    private final CryptoService crypto;
    private final PassphraseCrypto pc = new PassphraseCrypto();
    private final ObjectMapper json = new ObjectMapper();

    public LocalKeyStore(CliConfig config, CryptoService crypto) {
        this.config = config;
        this.crypto = crypto;
    }

    public boolean exists(String email) {
        return Files.exists(config.keyFile(email));
    }

    private static byte[] aad(String email) {
        return ("secureshare-key-v1:" + email.toLowerCase(Locale.ROOT)).getBytes(StandardCharsets.UTF_8);
    }

    public void save(String email, KeyPair pair, char[] passphrase) {
        byte[] pkcs8 = pair.getPrivate().getEncoded();
        PassphraseCrypto.Sealed sealed = pc.seal(pkcs8, passphrase, aad(email));
        Arrays.fill(pkcs8, (byte) 0);

        ObjectNode n = json.createObjectNode();
        n.put("version", 1);
        n.put("email", email.toLowerCase(Locale.ROOT));
        n.put("publicKey", crypto.encodePublicKey(pair.getPublic()));
        n.put("kdf", "PBKDF2WithHmacSHA256");
        n.put("iterations", sealed.iterations());
        n.put("salt", crypto.encodeBytes(sealed.salt()));
        n.put("iv", crypto.encodeBytes(sealed.iv()));
        n.put("encryptedPrivateKey", crypto.encodeBytes(sealed.ciphertext()));

        Path file = config.keyFile(email);
        try {
            Files.createDirectories(file.getParent());
            json.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), n);
            CliConfig.restrict(file);
        } catch (IOException e) {
            throw new CliException("Could not write key file " + file + ": " + e.getMessage());
        }
    }

    public Loaded load(String email, char[] passphrase) {
        Path file = config.keyFile(email);
        JsonNode n;
        try {
            n = json.readTree(file.toFile());
        } catch (IOException e) {
            throw new CliException("Could not read key file " + file + ": " + e.getMessage());
        }
        try {
            PassphraseCrypto.Sealed sealed = new PassphraseCrypto.Sealed(
                    n.path("iterations").asInt(),
                    crypto.decodeBytes(n.path("salt").asText()),
                    crypto.decodeBytes(n.path("iv").asText()),
                    crypto.decodeBytes(n.path("encryptedPrivateKey").asText()));
            byte[] pkcs8 = pc.open(sealed, passphrase, aad(email));
            PrivateKey priv = crypto.decodePrivateKey(Base64.getEncoder().encodeToString(pkcs8));
            Arrays.fill(pkcs8, (byte) 0);
            return new Loaded(priv, crypto.decodePublicKey(n.path("publicKey").asText()));
        } catch (WrongPassphraseException e) {
            throw new CliException("Wrong key passphrase (or the key file was modified)");
        } catch (CryptoException e) {
            throw new CliException("Key file is damaged: " + e.getMessage());
        }
    }
}
