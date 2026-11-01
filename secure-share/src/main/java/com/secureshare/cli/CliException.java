package com.secureshare.cli;

/** A user-facing failure: printed as "Error: <message>" and turned into an exit code. */
public class CliException extends RuntimeException {
    private final int exitCode;

    public CliException(String message) { this(message, 1); }

    public CliException(String message, int exitCode) {
        super(message);
        this.exitCode = exitCode;
    }

    public int exitCode() { return exitCode; }
}
