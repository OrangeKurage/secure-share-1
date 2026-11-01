package com.secureshare;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.secureshare.model.AuditLog;
import com.secureshare.model.FileShare;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

/** Phase 5 (sharing) + Phase 6 (download/decrypt/verify). Attack cases live in Phase9AttackTest. */
@SpringBootTest
@AutoConfigureMockMvc
class Phase56IntegrationTest extends ApiTestSupport {

    static final byte[] PLAIN = "Q3 board minutes - STRICTLY CONFIDENTIAL. ".repeat(300).getBytes(StandardCharsets.UTF_8);

    private boolean audited(long userId, String action, String status) {
        List<AuditLog> log = audits.findByUser_UserIdOrderByTimestampDesc(userId);
        return log.stream().anyMatch(a -> a.getAction().equals(action) && status.equals(a.getStatus()));
    }

    // ------------------------------------------------------------ happy path

    @Test
    void alice_sharesWithBobAndCarol_bothRecoverIdenticalFile_eveIsDenied() throws Exception {
        Client alice = newClient(), bob = newClient(), carol = newClient(), eve = newClient();
        long fileId = upload(alice, PLAIN);

        shareWith(alice, fileId, "DOWNLOAD", null, 200, bob, carol);

        // recipients see it in "shared with me"
        mvcGetShared(bob, fileId);
        mvcGetShared(carol, fileId);

        // each recipient decrypts with their OWN private key, integrity + signature pass
        assertThat(receive(bob, fileId)).isEqualTo(PLAIN);
        assertThat(receive(carol, fileId)).isEqualTo(PLAIN);
        assertThat(receive(alice, fileId)).isEqualTo(PLAIN);       // the owner can read their own file too

        // outsider: no bundle, no blob
        getAs(eve, "/files/" + fileId + "/bundle", 403);
        getAs(eve, "/files/" + fileId + "/download", 403);
        assertThat(audited(eve.userId(), "DOWNLOAD", "FAILURE")).isTrue();

        // audit trail for the legitimate recipient
        assertThat(audited(bob.userId(), "DOWNLOAD", "SUCCESS")).isTrue();
        assertThat(audited(bob.userId(), "VERIFY", "SUCCESS")).isTrue();
        assertThat(audited(alice.userId(), "SHARE", "SUCCESS")).isTrue();

        // owner's access list
        var list = body(getAs(alice, "/files/" + fileId + "/shares", 200));
        assertThat(list).hasSize(2);
    }

    private void mvcGetShared(Client c, long fileId) throws Exception {
        var arr = body(getAs(c, "/files/shared-with-me", 200));
        assertThat(arr.findValuesAsText("fileId")).contains(Long.toString(fileId));
        assertThat(arr.toString()).doesNotContain("wrappedKey");      // keys are only served via /bundle
    }

    // ------------------------------------------------- sharing rules (Phase 5)

    @Test
    void nonOwnerCannotShareOrRevokeOrListShares() throws Exception {
        Client alice = newClient(), bob = newClient(), mallory = newClient();
        long fileId = upload(alice, PLAIN);
        shareWith(alice, fileId, "DOWNLOAD", null, 200, bob);

        // Bob (a recipient, not the owner) cannot re-share; the "client" would need the key anyway,
        // so we just submit a syntactically valid request to prove the SERVER refuses.
        var bobsBundle = body(getAs(bob, "/files/" + fileId + "/bundle", 200));
        var req = Map.of("recipients", List.of(Map.of("email", mallory.email(),
                "wrappedKey", crypto.encodeBytes(crypto.wrapKey(
                        crypto.unwrapKey(crypto.decodeBytes(bobsBundle.get("wrappedKey").asText()), bob.keys().getPrivate()),
                        mallory.keys().getPublic())))));
        postJson(bob, "/files/" + fileId + "/share", req, 403);
        postJson(bob, "/files/" + fileId + "/revoke", Map.of("email", bob.email()), 403);
        getAs(bob, "/files/" + fileId + "/shares", 403);
        getAs(mallory, "/files/" + fileId + "/bundle", 403);                 // still no access
        assertThat(audited(bob.userId(), "SHARE", "FAILURE")).isTrue();
    }

    @Test
    void shareValidation_unknownEmail_self_duplicates_pastExpiry_badKey() throws Exception {
        Client alice = newClient(), bob = newClient();
        long fileId = upload(alice, PLAIN);

        // unknown recipient -> 404
        var ghost = new Client("ghost-" + bob.email(), -1, bob.keys(), bob.token());
        shareWith(alice, fileId, null, null, 404, ghost);
        // sharing with yourself -> 400
        shareWith(alice, fileId, null, null, 400, alice);
        // duplicate recipient -> 400
        shareWith(alice, fileId, null, null, 400, bob, bob);
        // expiry in the past -> 400
        shareWith(alice, fileId, "DOWNLOAD", Instant.now().minusSeconds(60), 400, bob);
        // wrapped key of the wrong length -> 400
        postJson(alice, "/files/" + fileId + "/share",
                Map.of("recipients", List.of(Map.of("email", bob.email(), "wrappedKey", "AAAA"))), 400);
        // nothing was granted by any of the failed attempts
        getAs(bob, "/files/" + fileId + "/bundle", 403);
    }

    @Test
    void revoke_blocksImmediately_andReShareReactivates() throws Exception {
        Client alice = newClient(), bob = newClient();
        long fileId = upload(alice, PLAIN);
        shareWith(alice, fileId, "DOWNLOAD", null, 200, bob);
        assertThat(receive(bob, fileId)).isEqualTo(PLAIN);

        postJson(alice, "/files/" + fileId + "/revoke", Map.of("email", bob.email()), 200);

        getAs(bob, "/files/" + fileId + "/bundle", 403);
        getAs(bob, "/files/" + fileId + "/download", 403);
        assertThat(body(getAs(bob, "/files/shared-with-me", 200)).findValuesAsText("fileId"))
                .doesNotContain(Long.toString(fileId));
        assertThat(body(getAs(alice, "/files/" + fileId + "/shares", 200)).get(0).get("status").asText())
                .isEqualTo("REVOKED");

        // owner changes their mind: re-sharing re-uses the row (no duplicate) and works again
        shareWith(alice, fileId, "DOWNLOAD", null, 200, bob);
        assertThat(receive(bob, fileId)).isEqualTo(PLAIN);
        assertThat(body(getAs(alice, "/files/" + fileId + "/shares", 200))).hasSize(1);
    }

    @Test
    void expiredShare_isBlocked_andHiddenFromList() throws Exception {
        Client alice = newClient(), bob = newClient();
        long fileId = upload(alice, PLAIN);
        shareWith(alice, fileId, "DOWNLOAD", Instant.now().plusSeconds(3600), 200, bob);
        assertThat(receive(bob, fileId)).isEqualTo(PLAIN);

        FileShare s = shares.findByFile_FileIdAndRecipient_UserId(fileId, bob.userId()).orElseThrow();
        s.setExpiryDate(Instant.now().minusSeconds(5));                    // time passes...
        shares.save(s);

        getAs(bob, "/files/" + fileId + "/bundle", 403);
        getAs(bob, "/files/" + fileId + "/download", 403);
        assertThat(body(getAs(bob, "/files/shared-with-me", 200)).findValuesAsText("fileId"))
                .doesNotContain(Long.toString(fileId));
        assertThat(body(getAs(alice, "/files/" + fileId + "/shares", 200)).get(0).get("status").asText())
                .isEqualTo("EXPIRED");
    }

    @Test
    void viewOnlyShare_canReadMetadata_butCannotDownloadBlob() throws Exception {
        Client alice = newClient(), bob = newClient();
        long fileId = upload(alice, PLAIN);
        shareWith(alice, fileId, "VIEW", null, 200, bob);

        var bundle = body(getAs(bob, "/files/" + fileId + "/bundle", 200));
        assertThat(bundle.get("permission").asText()).isEqualTo("VIEW");
        assertThat(bundle.get("fileName").asText()).isEqualTo("report.pdf");
        getAs(bob, "/files/" + fileId + "/download", 403);
        assertThat(audited(bob.userId(), "DOWNLOAD", "FAILURE")).isTrue();
    }

    @Test
    void unknownFile_gets403_notAnEnumerationOracle() throws Exception {
        Client bob = newClient();
        getAs(bob, "/files/99999999/bundle", 403);
        getAs(bob, "/files/99999999/download", 403);
        mvc.perform(get("/files/1/download")).andExpect(status().isUnauthorized());   // no token
    }
}
