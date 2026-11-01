package com.secureshare.cli;

import com.fasterxml.jackson.databind.JsonNode;
import picocli.CommandLine.Command;

@Command(name = "list-shared", description = "List files that others have shared with you.")
public class ListSharedCommand extends BaseCommand {
    @Override
    public Integer call() {
        JsonNode files = api().get("/files/shared-with-me");
        if (files.isEmpty()) {
            out("Nothing has been shared with you.");
            return 0;
        }
        out(String.format("%-6s %-28s %10s  %-26s %-9s %s", "ID", "NAME", "SIZE", "FROM", "ACCESS", "EXPIRES"));
        for (JsonNode f : files) {
            out(String.format("%-6d %-28s %10d  %-26s %-9s %s", f.get("fileId").asLong(), f.get("fileName").asText(),
                    f.get("fileSize").asLong(), f.get("ownerEmail").asText(), f.get("permission").asText(),
                    f.hasNonNull("expiryDate") ? f.get("expiryDate").asText() : "never"));
        }
        return 0;
    }
}
