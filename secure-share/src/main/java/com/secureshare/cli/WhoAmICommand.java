package com.secureshare.cli;

import com.fasterxml.jackson.databind.JsonNode;
import picocli.CommandLine.Command;

@Command(name = "whoami", description = "Show the account you are logged in as.")
public class WhoAmICommand extends BaseCommand {
    @Override
    public Integer call() {
        JsonNode me = api().get("/users/me");
        out(me.get("fullName").asText() + " <" + me.get("email").asText() + ">  id " + me.get("userId").asLong());
        out("Public key fingerprint: " + fingerprint(me.get("publicKey").asText()));
        return 0;
    }
}
