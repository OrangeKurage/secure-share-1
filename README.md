# Secure Share

Hybrid encryption file sharing. A file is encrypted on the sender's machine, shared with named recipients, and checked by the recipient before it is saved. The server stores ciphertext only.

## Cryptography

| Step | Algorithm |
|---|---|
| File encryption | AES-256-GCM, a new key and 96-bit IV for every file |
| Key wrapping | RSA-2048 OAEP with SHA-256 and MGF1-SHA-256, once per recipient |
| Integrity hash | SHA-256 of the plaintext |
| Signature | RSA-PSS, SHA-256, 32-byte salt, over that hash |
| Private key at rest | PBKDF2-HMAC-SHA256 (600,000 iterations) and AES-256-GCM |
| Account password | BCrypt |
| Login token | HMAC-SHA JWT. Logout revokes it immediately |

The file is encrypted once. Each extra recipient only wraps the same 32-byte session key.

On receive, the client unwraps the session key, checks the AES-GCM tag, and checks the signature against the sender's public key. If any check fails, the plaintext is not written. A successful receive reports:

`Integrity verified. Signature valid (sender: Alice).`

There is no certificate authority. Compare the public-key fingerprint out of band for anyone whose key you need to trust.

## Layout

```
secure-share/          Spring Boot server, CLI, and web page
secure-share/storage/  encrypted blobs (IV || ciphertext || GCM tag)
secure-share/data/     local H2 database
```

The database holds public keys, the SHA-256 hash, the signature, and the wrapped session keys. Private keys stay on the client: `~/.secureshare/keys/` for the CLI, or the browser's local storage for the web page.

## Run the server

Java 17 and Maven. From `secure-share`:

```powershell
mvn spring-boot:run
```

In IntelliJ, run **SecureShare (Run)**. The server listens on `http://localhost:8080`. `http://localhost:8080/health` returns `{"status":"ok"}`.

Set `JWT_SECRET` (at least 32 characters) before anyone else can reach the server. The built-in default is for local use only.

## Web page

Open `http://localhost:8080/`. Register each person in that browser, then log in, choose a file, add recipient emails, and send. The recipient logs in and clicks **Open**. Encryption and verification happen in the browser.

## Command line

One-time setup from `secure-share`:

```powershell
mvn -q package -DskipTests dependency:copy-dependencies "-DoutputDirectory=target/cli-lib" "-DincludeScope=runtime"
```

Then `cli\share.cmd` on Windows or `cli/share.sh` on Linux and macOS:

```text
share register --name "Alice" --email alice@example.com
share login    --email alice@example.com
share send report.pdf --to bob@example.com
share receive --file-id 1 --out report.pdf
```

Command details are in [secure-share/cli/README.md](secure-share/cli/README.md). The HTTP API is in [secure-share/docs/API.md](secure-share/docs/API.md).

## Tests

From `secure-share`:

```powershell
mvn test
```

In IntelliJ, run **SecureShare (All Tests)**.
