package com.secureshare.cli;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;

/** Secret input: option value > environment variable > hidden console prompt > plain stdin (IDE run windows). */
final class Prompt {
    private Prompt() {}

    static String secret(String label, String provided, String envVar) {
        if (provided != null) return provided;
        String env = envVar == null ? null : System.getenv(envVar);
        if (env != null && !env.isEmpty()) return env;
        Console console = System.console();
        if (console != null) {
            char[] chars = console.readPassword("%s", label);
            if (chars != null) return new String(chars);
        }
        System.err.print(label);
        System.err.flush();
        try {
            String line = new BufferedReader(new InputStreamReader(System.in)).readLine();
            if (line != null) return line;
        } catch (IOException ignored) {
            // fall through
        }
        throw new CliException("No input available for: " + label.trim());
    }
}
