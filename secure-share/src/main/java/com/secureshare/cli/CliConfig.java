package com.secureshare.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;

/** Per-user settings in <home>/config.json (server, current account, session token). Keys live in <home>/keys/. */
public final class CliConfig {

    private final Path home;
    private final Path file;
    private final ObjectMapper json = new ObjectMapper();
    private ObjectNode data;

    public static CliConfig open(String homeOption) {
        String env = System.getenv("SECURESHARE_HOME");
        Path home = homeOption != null ? Paths.get(homeOption)
                : env != null && !env.isBlank() ? Paths.get(env)
                : Paths.get(System.getProperty("user.home"), ".secureshare");
        return new CliConfig(home.toAbsolutePath().normalize());
    }

    private CliConfig(Path home) {
        this.home = home;
        this.file = home.resolve("config.json");
        try {
            JsonNode n = Files.exists(file) ? json.readTree(file.toFile()) : null;
            this.data = n instanceof ObjectNode o ? o : json.createObjectNode();
        } catch (IOException e) {
            throw new CliException("Could not read " + file + ": " + e.getMessage());
        }
    }

    public Path home() { return home; }

    public Path keyFile(String email) {
        String safe = email.toLowerCase().replaceAll("[^a-z0-9@._-]", "_");
        return home.resolve("keys").resolve(safe + ".key.json");
    }

    public String get(String key) {
        JsonNode n = data.get(key);
        return n == null || n.isNull() ? null : n.asText();
    }

    public void set(String key, String value) {
        if (value == null) data.remove(key);
        else data.put(key, value);
    }

    public void save() {
        try {
            Files.createDirectories(home);
            json.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), data);
            restrict(file);
        } catch (IOException e) {
            throw new CliException("Could not write " + file + ": " + e.getMessage());
        }
    }

    /** Best effort: owner-only permissions where the OS supports POSIX modes. */
    static void restrict(Path p) {
        try {
            Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException ignored) {
            // e.g. Windows: rely on the user profile's own ACLs
        }
    }
}
