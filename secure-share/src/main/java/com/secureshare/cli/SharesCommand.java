package com.secureshare.cli;

import com.fasterxml.jackson.databind.JsonNode;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "shares", description = "Show who has (or had) access to one of your files.")
public class SharesCommand extends BaseCommand {

    @Option(names = "--file-id", required = true) long fileId;

    @Override
    public Integer call() {
        JsonNode shares = api().get("/files/" + fileId + "/shares");
        if (shares.isEmpty()) {
            out("File " + fileId + " is not shared with anyone.");
            return 0;
        }
        out(String.format("%-30s %-9s %-8s %s", "RECIPIENT", "ACCESS", "STATUS", "EXPIRES"));
        for (JsonNode s : shares) {
            out(String.format("%-30s %-9s %-8s %s", s.get("recipientEmail").asText(), s.get("permission").asText(),
                    s.get("status").asText(), s.hasNonNull("expiryDate") ? s.get("expiryDate").asText() : "never"));
        }
        return 0;
    }
}
