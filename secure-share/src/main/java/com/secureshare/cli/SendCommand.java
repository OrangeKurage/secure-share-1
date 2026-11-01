package com.secureshare.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.secureshare.crypto.EncryptedPayload;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.crypto.SecretKey;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "send", description = "Encrypt a file on this machine, upload it, and optionally share it.")
public class SendCommand extends BaseCommand {

    @Parameters(index = "0", paramLabel = "FILE", description = "The file to send") Path file;
    @Option(names = "--to", split = ",", description = "Recipient email(s), comma separated") List<String> to = new ArrayList<>();
    @Option(names = "--permission", defaultValue = "DOWNLOAD", description = "VIEW or DOWNLOAD (default: ${DEFAULT-VALUE})")
    String permission;
    @Option(names = "--expires-in-days", description = "Access automatically ends after this many days") Integer expiresInDays;
    @Option(names = {"-p", "--password"}, description = "Password (prompted if omitted)") String password;

    @Override
    public Integer call() {
        if (!Files.isRegularFile(file)) throw new CliException("File not found: " + file);
        String perm = permission.toUpperCase(Locale.ROOT);
        if (!perm.equals("VIEW") && !perm.equals("DOWNLOAD")) throw new CliException("--permission must be VIEW or DOWNLOAD");
        if (expiresInDays != null && expiresInDays < 1) throw new CliException("--expires-in-days must be at least 1");

        ApiClient api = api();
        Identity me = unlock(password);

        // 1. Resolve every recipient FIRST, so a typo fails before anything is uploaded.
        Map<String, PublicKey> recipients = new LinkedHashMap<>();
        for (String raw : to) {
            String em = raw.trim().toLowerCase(Locale.ROOT);
            if (em.isEmpty() || recipients.containsKey(em)) continue;
            JsonNode u = api.get("/users/lookup?email=" + URLEncoder.encode(em, StandardCharsets.UTF_8));
            recipients.put(em, crypto().decodePublicKey(u.get("publicKey").asText()));
            out("Recipient " + em + "  key fingerprint " + fingerprint(u.get("publicKey").asText()));
        }

        // 2. Everything cryptographic happens here, on this machine.
        byte[] plain;
        try {
            plain = Files.readAllBytes(file);
        } catch (IOException e) {
            throw new CliException("Could not read " + file + ": " + e.getMessage());
        }
        SecretKey sessionKey = crypto().generateSessionKey();                       // fresh AES-256 key per file
        EncryptedPayload payload = crypto().encryptFile(plain, sessionKey);         // AES-256-GCM, fresh IV
        byte[] hash = crypto().hashFile(plain);                                     // SHA-256 of the plaintext
        byte[] signature = crypto().signHash(hash, me.privateKey());                // RSA-PSS
        byte[] ownWrapped = crypto().wrapKey(sessionKey, me.publicKey());          // RSA-OAEP, for myself

        // 3. Upload ciphertext + metadata only.
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("fileName", file.getFileName().toString());
        fields.put("sha256Hash", crypto().toHex(hash));
        fields.put("signature", crypto().encodeBytes(signature));
        fields.put("encryptedAesKey", crypto().encodeBytes(ownWrapped));
        JsonNode uploaded = api.postMultipart("/files/upload", fields, "file", payload.toBlob());
        long fileId = uploaded.get("fileId").asLong();
        out("Encrypted and uploaded " + file.getFileName() + " (file id " + fileId + ", " + plain.length + " bytes).");

        // 4. Wrap the SAME session key once per recipient (the file is never re-encrypted).
        if (!recipients.isEmpty()) {
            List<Map<String, String>> list = new ArrayList<>();
            for (Map.Entry<String, PublicKey> r : recipients.entrySet()) {
                list.add(Map.of("email", r.getKey(),
                        "wrappedKey", crypto().encodeBytes(crypto().wrapKey(sessionKey, r.getValue()))));
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("recipients", list);
            body.put("permission", perm);
            if (expiresInDays != null) body.put("expiresAt", Instant.now().plus(expiresInDays, ChronoUnit.DAYS).toString());
            api.postJson("/files/" + fileId + "/share", body);
            out("Shared (" + perm + ") with: " + String.join(", ", recipients.keySet())
                    + (expiresInDays != null ? "  [expires in " + expiresInDays + " days]" : ""));
        }
        return 0;
    }
}
