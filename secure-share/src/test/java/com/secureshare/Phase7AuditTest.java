package com.secureshare;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@AutoConfigureMockMvc
class Phase7AuditTest extends ApiTestSupport {

    static final byte[] PLAIN = "audit me".getBytes(StandardCharsets.UTF_8);

    @Test
    void me_listsOnlyMyEvents_newestFirst() throws Exception {
        Client alice = newClient();
        newClient();                                   // another user generating their own noise
        upload(alice, PLAIN);

        JsonNode log = body(getAs(alice, "/audit-log/me", 200));
        assertThat(log.findValuesAsText("action")).contains("REGISTER", "LOGIN", "UPLOAD");
        for (JsonNode e : log) {
            assertThat(e.get("userId").asLong()).isEqualTo(alice.userId());
        }
        Instant previous = Instant.MAX;
        for (JsonNode e : log) {
            Instant t = Instant.parse(e.get("timestamp").asText());
            assertThat(t).isBeforeOrEqualTo(previous);
            previous = t;
        }
    }

    @Test
    void fileLog_ownerSeesEveryonesActivity_othersAreRefused() throws Exception {
        Client alice = newClient(), bob = newClient(), eve = newClient();
        long fileId = upload(alice, PLAIN);
        shareWith(alice, fileId, "DOWNLOAD", null, 200, bob);
        receive(bob, fileId);
        getAs(eve, "/files/" + fileId + "/download", 403);      // an attempted break-in

        JsonNode log = body(getAs(alice, "/audit-log/file/" + fileId, 200));
        assertThat(log.findValuesAsText("action")).contains("UPLOAD", "SHARE", "DOWNLOAD", "VERIFY");
        assertThat(log.findValuesAsText("userEmail")).contains(alice.email(), bob.email(), eve.email());
        boolean evesFailureRecorded = false;
        for (JsonNode e : log) {
            if (eve.email().equals(e.path("userEmail").asText()) && "FAILURE".equals(e.get("status").asText())) {
                evesFailureRecorded = true;
            }
        }
        assertThat(evesFailureRecorded).isTrue();

        getAs(bob, "/audit-log/file/" + fileId, 403);            // recipients may not read the owner's log
        getAs(eve, "/audit-log/file/" + fileId, 403);
        getAs(alice, "/audit-log/file/99999999", 403);           // unknown file: same answer
    }

    @Test
    void limit_isHonoured_andClamped() throws Exception {
        Client alice = newClient();                    // REGISTER + LOGIN
        upload(alice, PLAIN);                          // + UPLOAD
        assertThat(body(getAs(alice, "/audit-log/me?limit=2", 200))).hasSize(2);
        assertThat(body(getAs(alice, "/audit-log/me?limit=0", 200))).hasSize(1);   // clamped up to 1
        assertThat(body(getAs(alice, "/audit-log/me", 200)).size()).isGreaterThanOrEqualTo(3);
    }

    @Test
    void auditEndpoints_requireLogin() throws Exception {
        mvc.perform(get("/audit-log/me")).andExpect(status().isUnauthorized());
        mvc.perform(get("/audit-log/file/1")).andExpect(status().isUnauthorized());
    }
}
