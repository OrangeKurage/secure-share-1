package com.secureshare.cli;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "register", description = "Create an account. Generates your RSA key pair locally.")
public class RegisterCommand extends BaseCommand {

    @Option(names = "--name", required = true, description = "Your display name") String name;
    @Option(names = "--email", required = true, description = "Your email address") String email;
    @Option(names = {"-p", "--password"}, description = "Password (prompted if omitted)") String password;
    @Option(names = "--server", description = "Server URL (default: $SHARE_SERVER or http://localhost:8080)")
    String server;

    @Override
    public Integer call() {
        String em = email.trim().toLowerCase(Locale.ROOT);
        String url = server != null ? server : System.getenv().getOrDefault("SHARE_SERVER", "http://localhost:8080");
        LocalStore store = store();
        if (store.hasKey(em)) {
            throw new CliException("A key file for " + em + " already exists on this device; refusing to overwrite it.");
        }

        char[] pw;
        if (password != null || System.getenv("SHARE_PASSWORD") != null) {
            pw = passwordOrPrompt(password, "");
        } else {
            pw = Prompts.password("Choose a password: ");
            char[] again = Prompts.password("Repeat the password: ");
            boolean same = Arrays.equals(pw, again);
            Arrays.fill(again, '\0');
            if (!same) throw new CliException("The passwords do not match");
        }
        if (pw.length < 8) throw new CliException("The password must be at least 8 characters");

        KeyPair kp = crypto().generateKeyPair();
        String publicKey = crypto().encodePublicKey(kp.getPublic());

        // Save the (encrypted) private key BEFORE telling the server, so a crash can never lock you out.
        byte[] pkcs8 = kp.getPrivate().getEncoded();
        store.saveKey(new LocalStore.StoredKey(em, publicKey, root.protector.protect(pkcs8, pw, em)));
        Arrays.fill(pkcs8, (byte) 0);

        try {
            new ApiClient(url, null).postJson("/users/register", Map.of(
                    "fullName", name, "email", em, "password", new String(pw), "publicKey", publicKey));
        } catch (RuntimeException e) {
            store.deleteKey(em);                       // the server refused: leave no orphan key behind
            throw e;
        } finally {
            Arrays.fill(pw, '\0');
        }
        out("Registered " + em + ".");
        out("Your private key was generated here and saved ENCRYPTED at " + store.keyPath(em));
        out("It never leaves this machine. Back it up: without it, files shared with you cannot be opened.");
        out("Next: share login --email " + em);
        return 0;
    }
}
