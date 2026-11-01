package com.secureshare.cli;

import com.secureshare.crypto.CryptoException;
import com.secureshare.crypto.CryptoService;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.concurrent.Callable;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.ParentCommand;
import picocli.CommandLine.Spec;

/** Shared plumbing for every sub-command. */
abstract class BaseCommand implements Callable<Integer> {

    @ParentCommand protected ShareCli root;
    @Spec protected CommandSpec spec;

    protected record Identity(String email, PublicKey publicKey, PrivateKey privateKey) {}

    protected CryptoService crypto() { return root.crypto; }

    protected LocalStore store() { return root.store(); }

    protected void out(String line) { spec.commandLine().getOut().println(line); }

    protected void err(String line) { spec.commandLine().getErr().println(line); }

    /** An API client for the logged-in session. */
    protected ApiClient api() {
        LocalStore.Session s = store().loadSession();
        return new ApiClient(s.server(), s.token());
    }

    /** The password from --password, then $SHARE_PASSWORD, else an interactive prompt. */
    protected char[] passwordOrPrompt(String given, String prompt) {
        if (given != null) return given.toCharArray();
        String env = System.getenv("SHARE_PASSWORD");
        if (env != null && !env.isEmpty()) return env.toCharArray();
        return Prompts.password(prompt);
    }

    /** Decrypts the logged-in user's private key with their password. Never contacts the server. */
    protected Identity unlock(String passwordOption) {
        LocalStore.Session s = store().loadSession();
        LocalStore.StoredKey stored = store().loadKey(s.email());
        char[] pw = passwordOrPrompt(passwordOption, "Password for " + s.email() + ": ");
        byte[] pkcs8 = null;
        try {
            pkcs8 = root.protector.unprotect(stored.privateKey(), pw, s.email());
            PrivateKey priv = crypto().decodePrivateKey(crypto().encodeBytes(pkcs8));
            return new Identity(s.email(), crypto().decodePublicKey(stored.publicKey()), priv);
        } catch (CryptoException e) {
            throw new CliException(e.getMessage());
        } finally {
            Arrays.fill(pw, '\0');
            if (pkcs8 != null) Arrays.fill(pkcs8, (byte) 0);
        }
    }

    /** Same fingerprint CryptoService prints, so whoami, lookup and send can be compared out of band. */
    protected String fingerprint(String publicKeyBase64) {
        return crypto().fingerprint(crypto().decodePublicKey(publicKeyBase64));
    }
}
