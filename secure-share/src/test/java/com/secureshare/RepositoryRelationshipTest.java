package com.secureshare;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.secureshare.model.*;
import com.secureshare.repository.*;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;

@DataJpaTest
class RepositoryRelationshipTest {

    @Autowired UserRepository users;
    @Autowired FileRepository files;
    @Autowired FileShareRepository shares;
    @Autowired AuditLogRepository audits;
    @Autowired SessionRepository sessions;
    @Autowired EntityManager em;

    private User newUser(String name, String email) {
        User u = new User();
        u.setFullName(name);
        u.setEmail(email);
        u.setPasswordHash("hash");
        u.setPublicKey("PUBKEY-" + name);
        return users.saveAndFlush(u);
    }

    private FileEntity newFile(User owner) {
        FileEntity f = new FileEntity();
        f.setOwner(owner);
        f.setFileName("report.pdf");
        f.setFileType("pdf");
        f.setStoragePath("storage/abc.enc");
        f.setEncryptedAesKey("WRAPPED-OWNER");
        f.setSha256Hash("a".repeat(64));
        f.setSignature("SIG");
        f.setFileSize(1234L);
        return files.saveAndFlush(f);
    }

    @Test
    void userFileShareAuditSession_relationshipsResolve() {
        User alice = newUser("Alice", "alice@x.com");
        User bob = newUser("Bob", "bob@x.com");
        FileEntity file = newFile(alice);

        FileShare share = new FileShare();
        share.setFile(file);
        share.setSender(alice);
        share.setRecipient(bob);
        share.setPermission(SharePermission.DOWNLOAD);
        share.setWrappedKey("WRAPPED-BOB");
        shares.saveAndFlush(share);

        AuditLog log = new AuditLog();
        log.setUser(alice);
        log.setFile(file);
        log.setAction("UPLOAD");
        log.setStatus("SUCCESS");
        audits.saveAndFlush(log);

        Session s = new Session();
        s.setUser(alice);
        s.setJwtToken("jwt");
        s.setExpiryTime(Instant.now().plusSeconds(3600));
        sessions.saveAndFlush(s);

        em.clear(); // force real reads from the DB

        assertThat(files.findByOwner_UserId(alice.getUserId())).hasSize(1);

        FileShare found = shares.findByFile_FileIdAndRecipient_UserId(file.getFileId(), bob.getUserId())
                .orElseThrow();
        assertThat(found.getStatus()).isEqualTo(ShareStatus.ACTIVE);
        assertThat(found.getShareDate()).isNotNull();
        assertThat(found.getWrappedKey()).isEqualTo("WRAPPED-BOB");
        assertThat(found.getSender().getEmail()).isEqualTo("alice@x.com");
        assertThat(found.getRecipient().getEmail()).isEqualTo("bob@x.com");
        assertThat(found.getFile().getOwner().getUserId()).isEqualTo(alice.getUserId());

        assertThat(shares.findByRecipient_UserId(bob.getUserId())).hasSize(1);
        assertThat(audits.findByUser_UserIdOrderByTimestampDesc(alice.getUserId())).hasSize(1);
        assertThat(audits.findByFile_FileIdOrderByTimestampDesc(file.getFileId())).hasSize(1);
        assertThat(sessions.findByJwtToken("jwt")).isPresent();
    }

    @Test
    void duplicateEmailRejected() {
        newUser("Alice", "dup@x.com");
        User again = new User();
        again.setFullName("Eve");
        again.setEmail("dup@x.com");
        again.setPasswordHash("h");
        again.setPublicKey("k");
        assertThatThrownBy(() -> users.saveAndFlush(again))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void fileWithoutOwnerRejected() {
        FileEntity f = new FileEntity();
        f.setFileName("x");
        f.setStoragePath("p");
        f.setEncryptedAesKey("k");
        f.setSha256Hash("a".repeat(64));
        f.setSignature("s");
        f.setFileSize(1);
        assertThatThrownBy(() -> files.saveAndFlush(f)).isInstanceOf(Exception.class);
    }
}
