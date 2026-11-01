package com.secureshare.cli;

import com.fasterxml.jackson.databind.JsonNode;
import picocli.CommandLine.Command;

@Command(name = "list-mine", description = "List the files you have uploaded.")
public class ListMineCommand extends BaseCommand {
    @Override
    public Integer call() {
        JsonNode files = api().get("/files/mine");
        if (files.isEmpty()) {
            out("You have not uploaded any files.");
            return 0;
        }
        out(String.format("%-6s %-32s %10s  %s", "ID", "NAME", "SIZE", "UPLOADED"));
        for (JsonNode f : files) {
            out(String.format("%-6d %-32s %10d  %s", f.get("fileId").asLong(), f.get("fileName").asText(),
                    f.get("fileSize").asLong(), f.get("uploadDate").asText()));
        }
        return 0;
    }
}
