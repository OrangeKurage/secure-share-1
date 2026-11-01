package com.secureshare.cli;

import java.util.Map;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "revoke", description = "Stop sharing a file with someone (takes effect immediately).")
public class RevokeCommand extends BaseCommand {

    @Option(names = "--file-id", required = true) long fileId;
    @Option(names = "--from", required = true, description = "Email of the recipient to cut off") String from;

    @Override
    public Integer call() {
        api().postJson("/files/" + fileId + "/revoke", Map.of("email", from));
        out("Revoked: " + from + " can no longer access file " + fileId + ".");
        out("(Anything they already downloaded and decrypted cannot be taken back.)");
        return 0;
    }
}
