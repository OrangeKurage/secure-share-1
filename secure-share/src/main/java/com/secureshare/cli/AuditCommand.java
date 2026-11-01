package com.secureshare.cli;

import com.fasterxml.jackson.databind.JsonNode;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "audit", description = "Show your activity log, or (for your own files) everyone's activity on a file.")
public class AuditCommand extends BaseCommand {

    @Option(names = "--file-id", description = "Show the log for one of your files instead of your own activity") Long fileId;
    @Option(names = "--limit", defaultValue = "50", description = "How many entries (default: ${DEFAULT-VALUE})") int limit;

    @Override
    public Integer call() {
        String path = fileId == null ? "/audit-log/me?limit=" + limit : "/audit-log/file/" + fileId + "?limit=" + limit;
        JsonNode log = api().get(path);
        if (log.isEmpty()) {
            out("No entries.");
            return 0;
        }
        out(String.format("%-25s %-10s %-20s %-6s %-26s %s", "TIME", "ACTION", "STATUS", "FILE", "USER", "IP"));
        for (JsonNode e : log) {
            out(String.format("%-25s %-10s %-20s %-6s %-26s %s", e.get("timestamp").asText(), e.get("action").asText(),
                    e.path("status").asText(""), e.hasNonNull("fileId") ? e.get("fileId").asText() : "-",
                    e.hasNonNull("userEmail") ? e.get("userEmail").asText() : "-", e.path("ipAddress").asText("")));
        }
        return 0;
    }
}
