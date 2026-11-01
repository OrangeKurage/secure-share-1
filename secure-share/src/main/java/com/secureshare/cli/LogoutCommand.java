package com.secureshare.cli;

import picocli.CommandLine.Command;

@Command(name = "logout", description = "End the session on the server and forget the token locally.")
public class LogoutCommand extends BaseCommand {
    @Override
    public Integer call() {
        LocalStore store = store();
        if (!store.hasSession()) {
            out("Not logged in.");
            return 0;
        }
        try {
            api().postJson("/users/logout", java.util.Map.of());
        } catch (CliException e) {
            err("Note: the server could not be told to end the session (" + e.getMessage() + ").");
        }
        store.clearSession();
        out("Logged out.");
        return 0;
    }
}
