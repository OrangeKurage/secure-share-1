# REST API summary (Phases 3-6)

All routes except `/health`, `/users/register`, `/users/login` need `Authorization: Bearer <jwt>`.
Errors are JSON `{status, error, message, timestamp}`.

| Method | Path | Who | Purpose |
|---|---|---|---|
| POST | /users/register | public | name, email, password, **publicKey** (client-generated RSA >= 2048) |
| POST | /users/login | public | returns JWT + expiry |
| POST | /users/logout | user | revokes the session; token dies immediately |
| GET | /users/me, /users/{id}/public-key, /users/lookup?email= | user | key directory |
| POST | /files/upload | user | multipart: `file` (IV‖ciphertext‖tag), fileName, sha256Hash, signature, encryptedAesKey |
| GET | /files/mine | user | files I own |
| POST | /files/{id}/share | owner | `{recipients:[{email, wrappedKey}], permission?, expiresAt?}` (all-or-nothing, re-grants after revoke) |
| POST | /files/{id}/revoke | owner | `{email}` |
| GET | /files/{id}/shares | owner | who has/had access (EXPIRED shown when past expiry) |
| GET | /files/shared-with-me | user | active, unexpired shares |
| GET | /files/{id}/bundle | owner / active recipient | metadata + caller's wrappedKey + signature + sender public key |
| GET | /files/{id}/download | owner / DOWNLOAD recipient | the encrypted blob |
| GET | /audit-log/me?limit= | user | my own events, newest first (limit 1-500, default 100) |
| GET | /audit-log/file/{id}?limit= | owner | every user's events on my file |
| POST | /files/{id}/receipt | owner / recipient | `{outcome: SUCCESS|FAILURE_INTEGRITY|FAILURE_SIGNATURE|FAILURE_KEY}` -> audit VERIFY |

Permission semantics: `VIEW` = metadata via /bundle only; `DOWNLOAD` = also the ciphertext blob.
(The server cannot stop a DOWNLOAD recipient from keeping a decrypted copy - inherent to any file sharing.)

Access denied always answers 403 with the same message, whether the file is missing or just not yours.

Audit actions: REGISTER, LOGIN, LOGOUT, UPLOAD, SHARE, REVOKE, VIEW, DOWNLOAD, VERIFY, LIST_SHARES.
