package com.secureshare.cli;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

final class Prompts {

    private Prompts() {}

    /** Hidden input on a real terminal; plain stdin line when there is no console (IDE, pipes). */
    static char[] password(String prompt) {
        java.io.Console console = System.console();
        if (console != null) {
            char[] pw = console.readPassword("%s", prompt);
            if (pw == null) throw new CliException("No password entered");
            return pw;
        }
        System.err.print(prompt);
        System.err.flush();
        try {
            String line = new BufferedReader(new InputStreamReader(System.in)).readLine();
            if (line == null) throw new CliException("No password entered (use --password or SHARE_PASSWORD)");
            return line.toCharArray();
        } catch (IOException e) {
            throw new CliException("Could not read the password: " + e.getMessage());
        }
    }
}
