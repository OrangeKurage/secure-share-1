package com.secureshare.cli;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Locale;
import java.util.Map;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "login", description = "Log in and store a session token locally.")
public class LoginCommand extends BaseCommand {

    @Option(names = "--email", required = true) String email;
    @Option(names = {"-p", "--password"}, description = "Password (prompted if omitted)") String password;
    @Option(names = "--server", description = "Server URL (default: $SHARE_SERVER or http://localhost:8080)")
    String server;

    @Override
    public Integer call() {
        String em = email.trim().toLowerCase(Locale.ROOT);
        String url = server != null ? server : System.getenv().getOrDefault("SHARE_SERVER", "http://localhost:8080");
        char[] pw = passwordOrPrompt(password, "Password for " + em + ": ");
        JsonNode r = new ApiClient(url, null).postJson("/users/login", Map.of("email", em, "password", new String(pw)));
        java.util.Arrays.fill(pw, '\0');

        LocalStore store = store();
        store.saveSession(new LocalStore.Session(url, em, r.get("userId").asLong(),
                r.get("token").asText(), r.get("expiresAt").asText()));
        out("Logged in as " + r.get("fullName").asText() + " (" + em + "). Session expires " + r.get("expiresAt").asText() + ".");
        if (!store.hasKey(em)) {
            err("Warning: there is no private key for " + em + " on this device, so you cannot send or receive files here.");
        }
        return 0;
    }
}
