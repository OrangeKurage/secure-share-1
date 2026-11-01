package com.secureshare.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.secureshare.crypto.PrivateKeyProtector;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;

/**
 * Everything the CLI keeps on the user's machine, under ~/.secureshare (or $SHARE_HOME, or -Dsecureshare.home):
 *   session.json          current login (server URL + JWT)
 *   keys/<email>.json     the user's RSA private key, ENCRYPTED with their password. Never leaves this machine.
 */
public class LocalStore {

    public record Session(String server, String email, long userId, String token, String expiresAt) {}

    public record StoredKey(String email, String publicKey, PrivateKeyProtector.Protected privateKey) {}

    private final Path home;
    private final ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    public LocalStore(Path home) {
        this.home = home;
    }

    public static Path defaultHome() {
        String p = System.getProperty("secureshare.home");
        if (p == null || p.isBlank()) p = System.getenv("SHARE_HOME");
        if (p == null || p.isBlank()) return Paths.get(System.getProperty("user.home"), ".secureshare");
        return Paths.get(p);
    }

    public Path home() { return home; }

    // ---------------------------------------------------------------- session

    public void saveSession(Session s) { write(home.resolve("session.json"), s); }

    public boolean hasSession() { return Files.exists(home.resolve("session.json")); }

    public Session loadSession() {
        Path p = home.resolve("session.json");
        if (!Files.exists(p)) throw new CliException("Not logged in. Run: share login --email <you@example.com>");
        return read(p, Session.class);
    }

    public void clearSession() {
        try {
            Files.deleteIfExists(home.resolve("session.json"));
        } catch (IOException e) {
            throw new CliException("Could not remove the local session: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------- keys

    public Path keyPath(String email) {
        String safe = email.trim().toLowerCase().replaceAll("[^a-z0-9._@-]", "_");
        return home.resolve("keys").resolve(safe + ".json");
    }

    public boolean hasKey(String email) { return Files.exists(keyPath(email)); }

    public void saveKey(StoredKey key) { write(keyPath(key.email()), key); }

    public void deleteKey(String email) {
        try {
            Files.deleteIfExists(keyPath(email));
        } catch (IOException ignored) {
            // best effort
        }
    }

    public StoredKey loadKey(String email) {
        Path p = keyPath(email);
        if (!Files.exists(p)) {
            throw new CliException("No private key for " + email + " on this device (expected " + p
                    + "). Register on this device, or copy your key file here.");
        }
        return read(p, StoredKey.class);
    }

    // ---------------------------------------------------------------- helpers

    private void write(Path path, Object value) {
        try {
            Files.createDirectories(path.getParent());
            Files.write(path, mapper.writeValueAsBytes(value));
            restrictToOwner(path);
        } catch (IOException e) {
            throw new CliException("Could not write " + path + ": " + e.getMessage());
        }
    }

    /** Key and session files hold secrets. Owner-only on POSIX; drop inherited ACLs on Windows. */
    private static void restrictToOwner(Path path) {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
            return;
        } catch (UnsupportedOperationException ignored) {
            // Windows
        } catch (IOException ignored) {
            return;
        }
        String user = System.getenv("USERNAME");
        if (user == null || user.isBlank()) user = System.getProperty("user.name");
        if (user == null || user.isBlank()) return;
        try {
            new ProcessBuilder("icacls", path.toString(), "/inheritance:r", "/grant:r", user + ":(R,W)")
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .redirectError(ProcessBuilder.Redirect.DISCARD)
                    .start()
                    .waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (IOException ignored) {
            // best effort; the file is still written
        }
    }

    private <T> T read(Path path, Class<T> type) {
        try {
            return mapper.readValue(Files.readAllBytes(path), type);
        } catch (IOException e) {
            throw new CliException("Could not read " + path + ": " + e.getMessage());
        }
    }
}
