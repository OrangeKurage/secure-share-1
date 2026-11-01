# secure-share CLI

Everything cryptographic happens on **your** machine. The server only ever receives ciphertext, wrapped keys,
hashes and signatures.

## Run it

Easiest (IntelliJ): open `cli/` run configuration **SecureShare CLI**, edit *Program arguments*, press Run.

From a terminal, one-time setup in the project root:

    mvn -q package -DskipTests dependency:copy-dependencies "-DoutputDirectory=target/cli-lib" "-DincludeScope=runtime"

then use `cli\share.cmd` (Windows) or `cli/share.sh` (Linux/macOS) as `share`:

    share register --name "Alice" --email alice@example.com
    share login    --email alice@example.com
    share send report.pdf --to bob@example.com,carol@example.com
    share send plans.pdf  --to bob@example.com --permission VIEW --expires-in-days 7
    share list-mine
    share list-shared
    share receive --file-id 12 --out report.pdf
    share shares  --file-id 12
    share revoke  --file-id 12 --from bob@example.com
    share audit                      # my own activity
    share audit   --file-id 12       # everyone's activity on my file
    share lookup  --email bob@example.com   # shows Bob's key fingerprint
    share whoami | logout | --help

Server defaults to `http://localhost:8080` (`--server` on register/login, or `SHARE_SERVER`).
The password is prompted unless you pass `-p` or set `SHARE_PASSWORD`.

## Where things are stored (`~/.secureshare`, override with `SHARE_HOME`)

| File | Contents |
|---|---|
| `keys/<email>.json` | your RSA private key, **encrypted** (PBKDF2-HMAC-SHA256 600k iterations + AES-256-GCM) |
| `session.json` | server URL + current login token |

Back up your key file. Lose it and files shared with you can never be opened.

## Exit codes
`0` success - `1` error (wrong password, no access, server unreachable, ...) - `2` verification FAILED
(tampered file / bad signature / not an intended recipient). On exit code 2 nothing is written to disk.

## Honest limitations
* The server sees your account password at login (BCrypt-hashed afterwards). Use HTTPS in any real deployment.
* Public keys come from the server's directory. Compare the fingerprint from `share lookup` out-of-band
  for anyone you really care about (the SRS excludes a certificate authority).
