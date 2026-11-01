package com.secureshare.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.secureshare.crypto.CryptoException;
import com.secureshare.crypto.EncryptedPayload;
import com.secureshare.crypto.UnauthorizedRecipientException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.PublicKey;
import java.util.Map;
import javax.crypto.SecretKey;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "receive", description = "Download a file, decrypt it, and verify its integrity and sender.")
public class ReceiveCommand extends BaseCommand {

    static final int VERIFICATION_FAILED = 2;

    @Option(names = "--file-id", required = true) long fileId;
    @Option(names = "--out", description = "Where to save the file (default: its original name, here)") Path outPath;
    @Option(names = "--force", description = "Overwrite the output file if it exists") boolean force;
    @Option(names = {"-p", "--password"}, description = "Password (prompted if omitted)") String password;

    @Override
    public Integer call() {
        ApiClient api = api();
        Identity me = unlock(password);

        JsonNode bundle = api.get("/files/" + fileId + "/bundle");
        String senderName = bundle.get("ownerName").asText();
        String senderEmail = bundle.get("ownerEmail").asText();
        Path target = outPath != null ? outPath : Paths.get(safeName(bundle.get("fileName").asText()));
        if (Files.exists(target) && !force) {
            throw new CliException("Refusing to overwrite " + target + " (use --force or --out)");
        }
        if ("VIEW".equals(bundle.get("permission").asText())) {
            throw new CliException("This file was shared with you as view-only; downloading is not permitted.");
        }
        byte[] blob = api.getBytes("/files/" + fileId + "/download");

        // --- 1. unwrap the session key: only the intended recipient's private key can do this
        SecretKey sessionKey;
        try {
            sessionKey = crypto().unwrapKey(crypto().decodeBytes(bundle.get("wrappedKey").asText()), me.privateKey());
        } catch (UnauthorizedRecipientException e) {
            report(api, "FAILURE_KEY");
            err("Access denied: your key cannot open this file. You are not an intended recipient.");
            return VERIFICATION_FAILED;
        }

        // --- 2. decrypt: AES-GCM authenticates the ciphertext, so any modification is caught here
        byte[] plain;
        try {
            EncryptedPayload p = EncryptedPayload.fromBlob(blob);
            plain = crypto().decryptFile(p.ciphertext(), p.iv(), sessionKey);
        } catch (CryptoException e) {
            report(api, "FAILURE_INTEGRITY");
            err("Integrity check FAILED: the encrypted file was modified or corrupted. Nothing was saved.");
            return VERIFICATION_FAILED;
        }

        // --- 3. hash must match what the sender signed, and the signature must verify against the sender's key
        byte[] hash = crypto().hashFile(plain);
        boolean signatureOk;
        try {
            PublicKey senderKey = crypto().decodePublicKey(bundle.get("ownerPublicKey").asText());
            signatureOk = crypto().toHex(hash).equals(bundle.get("sha256Hash").asText())
                    && crypto().verifySignature(crypto().decodeBytes(bundle.get("signature").asText()), hash, senderKey);
        } catch (CryptoException e) {
            signatureOk = false;
        }
        if (!signatureOk) {
            report(api, "FAILURE_SIGNATURE");
            err("Signature INVALID: this file is not authentically from " + senderName + " <" + senderEmail
                    + ">. Treat it as untrusted. Nothing was saved.");
            return VERIFICATION_FAILED;
        }

        // --- 4. only now, after every check passed, does plaintext touch the disk
        save(plain, target);
        report(api, "SUCCESS");
        out("Integrity verified. Signature valid (sender: " + senderName + "). File saved to " + target + ".");
        return 0;
    }

    private void report(ApiClient api, String outcome) {
        try {
            api.postJson("/files/" + fileId + "/receipt", Map.of("outcome", outcome));
        } catch (CliException e) {
            err("Warning: could not report the result to the server (" + e.getMessage() + ").");
        }
    }

    private static void save(byte[] plain, Path target) {
        try {
            Path abs = target.toAbsolutePath();
            Files.createDirectories(abs.getParent());
            Path tmp = Files.createTempFile(abs.getParent(), ".share-", ".tmp");
            try {
                Files.write(tmp, plain);
                Files.move(tmp, abs, StandardCopyOption.REPLACE_EXISTING);
            } finally {
                Files.deleteIfExists(tmp);
            }
        } catch (IOException e) {
            throw new CliException("Could not save the file: " + e.getMessage());
        }
    }

    private static String safeName(String name) {
        String n = name.replaceAll("[\\\\/]", "_").trim();
        return n.isEmpty() ? "download.bin" : n;
    }
}
