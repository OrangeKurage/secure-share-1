package com.secureshare;

import static org.assertj.core.api.Assertions.assertThat;

import com.secureshare.cli.LocalStore;
import com.secureshare.cli.ShareCli;
import com.secureshare.model.FileEntity;
import com.secureshare.repository.FileRepository;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import picocli.CommandLine;

/**
 * Drives the real CLI (in-process) against a real running server on a random port.
 * Each person gets their own "home" directory, exactly like separate computers would have.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CliEndToEndTest {

    static final String PW = "SecurePass123";

    @LocalServerPort int port;
    @Autowired FileRepository files;
    @Value("${app.storage.path}") String storagePath;
    @TempDir Path tmp;

    record Result(int exit, String out, String err) {}

    record Person(String name, String email, Path home) {}

    @BeforeAll
    static void fastKdf() {
        System.setProperty("secureshare.kdf.iterations", "1000");   // tests only: real default is 600,000
    }

    @AfterAll
    static void restore() {
        System.clearProperty("secureshare.kdf.iterations");
        System.clearProperty("secureshare.home");
    }

    // ------------------------------------------------------------ helpers

    private Result run(Path home, String... args) {
        System.setProperty("secureshare.home", home.toString());
        StringWriter out = new StringWriter(), err = new StringWriter();
        CommandLine cmd = ShareCli.newCommandLine();
        cmd.setOut(new PrintWriter(out, true));
        cmd.setErr(new PrintWriter(err, true));
        int exit = cmd.execute(args);
        return new Result(exit, out.toString(), err.toString());
    }

    private String server() { return "http://localhost:" + port; }

    private Person signUp(String who) {
        String email = who + "-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
        Path home = tmp.resolve(who);
        Result reg = run(home, "register", "--name", who, "--email", email, "--password", PW, "--server", server());
        assertThat(reg.exit()).as("register: " + reg.err()).isZero();
        Result login = run(home, "login", "--email", email, "--password", PW, "--server", server());
        assertThat(login.exit()).as("login: " + login.err()).isZero();
        return new Person(who, email, home);
    }

    private static long fileIdFrom(String output) {
        Matcher m = Pattern.compile("file id (\\d+)").matcher(output);
        assertThat(m.find()).as("no file id in: " + output).isTrue();
        return Long.parseLong(m.group(1));
    }

    private Path writeFile(String name, String text, int repeat) throws Exception {
        Path p = tmp.resolve(name);
        Files.write(p, text.repeat(repeat).getBytes(StandardCharsets.UTF_8));
        return p;
    }

    private Result receive(Person who, long fileId, Path out) {
        return run(who.home(), "receive", "--file-id", Long.toString(fileId), "--out", out.toString(), "-p", PW);
    }

    // -------------------------------------------------------------- tests

    @Test
    void fullFlow_sendShareReceiveRevokeAudit() throws Exception {
        Person alice = signUp("alice"), bob = signUp("bob"), carol = signUp("carol"), eve = signUp("eve");
        Path doc = writeFile("report.txt", "Quarterly numbers: CONFIDENTIAL. ", 100);
        byte[] original = Files.readAllBytes(doc);

        Result send = run(alice.home(), "send", doc.toString(), "--to", bob.email() + "," + carol.email(), "-p", PW);
        assertThat(send.exit()).as(send.err()).isZero();
        assertThat(send.out()).contains("Shared (DOWNLOAD) with");
        long fileId = fileIdFrom(send.out());

        // the server holds only ciphertext
        FileEntity stored = files.findById(fileId).orElseThrow();
        byte[] onDisk = Files.readAllBytes(Path.of(storagePath).toAbsolutePath().resolve(stored.getStoragePath()));
        assertThat(new String(onDisk, StandardCharsets.ISO_8859_1)).doesNotContain("CONFIDENTIAL");

        // recipients see it, open it, and the SRS success message is printed
        Result listed = run(bob.home(), "list-shared");
        assertThat(listed.out()).contains("report.txt").contains(alice.email());

        Path bobCopy = tmp.resolve("bob-copy.txt");
        Result bobGets = receive(bob, fileId, bobCopy);
        assertThat(bobGets.exit()).as(bobGets.err()).isZero();
        assertThat(bobGets.out()).contains("Integrity verified. Signature valid (sender: alice");
        assertThat(Files.readAllBytes(bobCopy)).isEqualTo(original);

        Path carolCopy = tmp.resolve("carol-copy.txt");
        assertThat(receive(carol, fileId, carolCopy).exit()).isZero();
        assertThat(Files.readAllBytes(carolCopy)).isEqualTo(original);

        // outsider: refused, nothing written
        Path evesCopy = tmp.resolve("eve-copy.txt");
        Result evesTry = receive(eve, fileId, evesCopy);
        assertThat(evesTry.exit()).isNotZero();
        assertThat(evesTry.err()).containsIgnoringCase("access");
        assertThat(evesCopy).doesNotExist();

        // owner manages access
        Result shares = run(alice.home(), "shares", "--file-id", Long.toString(fileId));
        assertThat(shares.out()).contains(bob.email()).contains(carol.email()).contains("ACTIVE");
        assertThat(run(alice.home(), "revoke", "--file-id", Long.toString(fileId), "--from", bob.email()).exit()).isZero();

        Path bobAfter = tmp.resolve("bob-after-revoke.txt");
        Result bobBlocked = receive(bob, fileId, bobAfter);
        assertThat(bobBlocked.exit()).isNotZero();
        assertThat(bobAfter).doesNotExist();
        assertThat(receive(carol, fileId, tmp.resolve("carol-again.txt")).exit()).isZero();   // others unaffected

        // the owner's audit trail tells the whole story
        Result audit = run(alice.home(), "audit", "--file-id", Long.toString(fileId));
        assertThat(audit.exit()).as(audit.err()).isZero();
        assertThat(audit.out()).contains("UPLOAD", "SHARE", "REVOKE", "DOWNLOAD", "VERIFY");
    }

    @Test
    void tamperedFileOnServer_isRejected_exit2_nothingSaved() throws Exception {
        Person alice = signUp("alice"), carol = signUp("carol");
        Path doc = writeFile("secret.txt", "do not tamper ", 200);
        long fileId = fileIdFrom(run(alice.home(), "send", doc.toString(), "--to", carol.email(), "-p", PW).out());

        FileEntity stored = files.findById(fileId).orElseThrow();
        Path blob = Path.of(storagePath).toAbsolutePath().resolve(stored.getStoragePath());
        byte[] bytes = Files.readAllBytes(blob);
        bytes[30] ^= 0x01;                                          // flip one bit of ciphertext
        Files.write(blob, bytes);

        Path out = tmp.resolve("carol-secret.txt");
        Result r = receive(carol, fileId, out);
        assertThat(r.exit()).isEqualTo(2);
        assertThat(r.err()).contains("Integrity check FAILED");
        assertThat(out).doesNotExist();

        Result audit = run(alice.home(), "audit", "--file-id", Long.toString(fileId));
        assertThat(audit.out()).contains("FAILURE_INTEGRITY");
    }

    @Test
    void wrongPassword_isRejected_andNothingIsUploaded() throws Exception {
        Person alice = signUp("alice");
        Path doc = writeFile("a.txt", "hello", 1);
        Result r = run(alice.home(), "send", doc.toString(), "-p", "not-the-password");
        assertThat(r.exit()).isEqualTo(1);
        assertThat(r.err()).contains("Wrong password");
        assertThat(run(alice.home(), "list-mine").out()).contains("not uploaded any files");
    }

    @Test
    void privateKeyFile_isEncryptedAtRest() throws Exception {
        Person alice = signUp("alice");
        String keyFile = Files.readString(new LocalStore(alice.home()).keyPath(alice.email()));
        assertThat(keyFile).contains("ciphertext").contains("PBKDF2WithHmacSHA256");
        assertThat(keyFile).doesNotContain("MIIEv");                // an unencrypted RSA PKCS#8 key starts like this
    }

    @Test
    void register_duplicateEmail_isRefused_andLeavesNoKeyBehind() throws Exception {
        Person alice = signUp("alice");
        Path otherDevice = tmp.resolve("other-device");
        Result r = run(otherDevice, "register", "--name", "Impostor", "--email", alice.email(),
                "--password", PW, "--server", server());
        assertThat(r.exit()).isNotZero();
        assertThat(r.err()).contains("already exists");
        assertThat(new LocalStore(otherDevice).hasKey(alice.email())).isFalse();
    }

    @Test
    void commandsNeedLogin() {
        Result r = run(tmp.resolve("nobody"), "list-shared");
        assertThat(r.exit()).isEqualTo(1);
        assertThat(r.err()).contains("Not logged in");
    }

    @Test
    void viewOnlyShare_cannotBeDownloaded_andLogoutEndsSession() throws Exception {
        Person alice = signUp("alice"), bob = signUp("bob");
        Path doc = writeFile("view.txt", "look but do not touch ", 10);
        long fileId = fileIdFrom(run(alice.home(), "send", doc.toString(), "--to", bob.email(),
                "--permission", "VIEW", "-p", PW).out());

        assertThat(run(bob.home(), "list-shared").out()).contains("VIEW");
        Result r = receive(bob, fileId, tmp.resolve("view-copy.txt"));
        assertThat(r.exit()).isEqualTo(1);
        assertThat(r.err()).contains("view-only");

        assertThat(run(bob.home(), "logout").exit()).isZero();
        assertThat(run(bob.home(), "list-shared").err()).contains("Not logged in");
    }

    @Test
    void lookupAndWhoami_showKeyFingerprint() throws Exception {
        Person alice = signUp("alice"), bob = signUp("bob");
        Result mine = run(alice.home(), "whoami");
        Result theirs = run(bob.home(), "lookup", "--email", bob.email());
        assertThat(mine.out()).contains("fingerprint");
        assertThat(theirs.out()).contains("fingerprint").contains(bob.email());
    }
}
