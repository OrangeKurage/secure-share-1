# Tool report

Paste each block into the report. Take the screenshots on your machine while the server, Postman, or SonarQube is actually running, and put the caption under the image.

## JUnit

**Name.** JUnit 5 (run by Maven Surefire).

**Purpose.** JUnit runs automated tests against the program and reports which checks passed or failed. It is used here to show that encryption, sharing, access control, and the attack cases behave as specified.

**Usage in this project.** Tests live in `secure-share/src/test/java`. `CryptoServiceTest` checks AES-GCM, RSA-OAEP, SHA-256, and RSA-PSS directly. `Phase34IntegrationTest`, `Phase56IntegrationTest`, `Phase7AuditTest`, and `Phase9AttackTest` call the running API: registration, upload of ciphertext only, sharing, revocation, audit, tampering, and a forged signature. `CliEndToEndTest` drives the command-line client. From `secure-share`, run `mvn test`. In IntelliJ, run **SecureShare (All Tests)**.

**Screenshot.** The IntelliJ test runner after **SecureShare (All Tests)**, with the green result and the test classes listed.

*Caption.* JUnit results for Secure Share. The suite covers cryptographic round trips, the REST API, the command-line client, and rejected tampered or forged files.

## Postman

**Name.** Postman.

**Purpose.** Postman sends HTTP requests to a running server and shows the status code and body. It is used here to exercise the REST API independently of the web page and the command line.

**Usage in this project.** Import `secure-share/postman/Secure-Share.postman_collection.json`. Start the server, register a user in the browser or with the CLI, then set the collection variables `email` and `password` to that account. Run **Login**. The collection stores the returned JWT and sends it as `Authorization: Bearer` on **Who am I**, **Lookup public key**, **My files**, **Shared with me**, and **My audit log**. **Logout** revokes that token. The same routes are listed in `secure-share/docs/API.md`.

**Screenshot.** Postman after **Login**, showing HTTP 200 and a `token` in the JSON body, and a second request such as **My files** that uses that token.

*Caption.* Postman calling the Secure Share API. Login returns a JWT, and the following request uses that token to read the authenticated user's files.

## SonarQube, with Docker

**Name.** SonarQube Community, started with Docker.

**Purpose.** SonarQube analyses source code and reports bugs, vulnerabilities, and maintainability issues. Docker runs the SonarQube server in a container so it does not have to be installed directly on the machine.

**Usage in this project.** From `secure-share`, with Docker Desktop running, start the server with `docker compose up -d`. Open `http://localhost:9000`, sign in as `admin` / `admin`, and set a new password when asked. Create a project with key `secure-share` and generate a token. Then run:

```text
mvn clean verify sonar:sonar -Dsonar.host.url=http://localhost:9000 -Dsonar.token=YOUR_TOKEN
```

The Maven plugin is `sonar-maven-plugin` in `pom.xml`. The project key is `secure-share`. The scanner reads `src/main/java` and the JUnit tests, then publishes the result to the local SonarQube server.

**Screenshots.** Docker Desktop, or `docker ps`, showing the `sonarqube` container in the running state. The SonarQube project overview for `secure-share` after the Maven scan.

*Caption (Docker).* The SonarQube server running in Docker and published on port 9000.

*Caption (SonarQube).* SonarQube analysis of the Secure Share source, produced by the Maven scanner.
