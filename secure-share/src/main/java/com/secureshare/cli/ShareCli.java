package com.secureshare.cli;

import com.secureshare.crypto.CryptoException;
import com.secureshare.crypto.CryptoService;
import com.secureshare.crypto.PrivateKeyProtector;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Spec;

@Command(name = "share",
        mixinStandardHelpOptions = true,
        version = "secure-share CLI 1.0",
        description = "Hybrid-encrypted file sharing. Files are encrypted, hashed and signed on THIS machine; "
                + "the server only ever sees ciphertext.",
        subcommands = {
                RegisterCommand.class, LoginCommand.class, LogoutCommand.class, WhoAmICommand.class,
                SendCommand.class, ListMineCommand.class, ListSharedCommand.class, ReceiveCommand.class,
                RevokeCommand.class, SharesCommand.class, AuditCommand.class, LookupCommand.class,
                CommandLine.HelpCommand.class})
public class ShareCli implements Runnable {

    @Spec CommandSpec spec;

    final CryptoService crypto = new CryptoService();
    final PrivateKeyProtector protector = new PrivateKeyProtector();

    LocalStore store() {
        return new LocalStore(LocalStore.defaultHome());
    }

    @Override
    public void run() {
        spec.commandLine().usage(spec.commandLine().getOut());
    }

    /** Builds the command line with friendly error handling (also used by the integration tests). */
    public static CommandLine newCommandLine() {
        CommandLine cmd = new CommandLine(new ShareCli());
        cmd.setExecutionExceptionHandler((ex, commandLine, parseResult) -> {
            if (ex instanceof CliException ce) {
                commandLine.getErr().println("Error: " + ce.getMessage());
                return ce.exitCode();
            }
            if (ex instanceof CryptoException) {
                commandLine.getErr().println("Error: " + ex.getMessage());
                return 1;
            }
            commandLine.getErr().println("Unexpected error: " + ex);
            return 1;
        });
        return cmd;
    }

    public static void main(String[] args) {
        System.exit(newCommandLine().execute(args));
    }
}
