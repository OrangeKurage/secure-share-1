package com.secureshare.cli;

import com.fasterxml.jackson.databind.JsonNode;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "lookup", description = "Look up a user's public key. Compare the fingerprint with them out-of-band.")
public class LookupCommand extends BaseCommand {

    @Option(names = "--email", required = true) String email;

    @Override
    public Integer call() {
        JsonNode u = api().get("/users/lookup?email=" + URLEncoder.encode(email, StandardCharsets.UTF_8));
        out(u.get("fullName").asText() + " <" + u.get("email").asText() + ">  id " + u.get("userId").asLong());
        out("Public key fingerprint: " + fingerprint(u.get("publicKey").asText()));
        return 0;
    }
}
