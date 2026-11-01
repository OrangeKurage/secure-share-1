-- Reference DDL (what Hibernate generates from the entities). Not auto-executed.
-- Deviations from the SRS ER diagram, to mention in the report:
--  * file_share has UNIQUE(file_id, recipient_id): one row per recipient, re-granted by update
--  * tables renamed users/files/sessions ("User" is reserved in H2/PostgreSQL)
--  * snake_case column names; enum values stored upper-case (VIEW, ACTIVE, ...)
--  * file_share.wrapped_key added (per-recipient wrapped session key)
--  * IV is NOT a column: the blob on disk is IV(12 bytes) || ciphertext || GCM tag
CREATE TABLE users (
  user_id BIGINT AUTO_INCREMENT PRIMARY KEY, full_name VARCHAR(100) NOT NULL,
  email VARCHAR(100) NOT NULL UNIQUE, password_hash VARCHAR(255) NOT NULL,
  public_key TEXT NOT NULL, created_at TIMESTAMP NOT NULL, last_login TIMESTAMP);
CREATE TABLE files (
  file_id BIGINT AUTO_INCREMENT PRIMARY KEY, owner_id BIGINT NOT NULL REFERENCES users(user_id),
  file_name VARCHAR(255) NOT NULL, file_type VARCHAR(20), storage_path VARCHAR(255) NOT NULL,
  upload_date TIMESTAMP NOT NULL, encrypted_aes_key TEXT NOT NULL, sha256_hash VARCHAR(64) NOT NULL,
  signature TEXT NOT NULL, file_size BIGINT NOT NULL);
CREATE TABLE file_share (
  share_id BIGINT AUTO_INCREMENT PRIMARY KEY, file_id BIGINT NOT NULL REFERENCES files(file_id),
  sender_id BIGINT NOT NULL REFERENCES users(user_id), recipient_id BIGINT NOT NULL REFERENCES users(user_id),
  permission VARCHAR(20) NOT NULL CHECK (permission IN ('VIEW','DOWNLOAD')), expiry_date TIMESTAMP,
  share_date TIMESTAMP NOT NULL, status VARCHAR(20) NOT NULL CHECK (status IN ('ACTIVE','REVOKED','EXPIRED')),
  wrapped_key TEXT NOT NULL);
CREATE TABLE audit_log (
  log_id BIGINT AUTO_INCREMENT PRIMARY KEY, user_id BIGINT REFERENCES users(user_id),
  file_id BIGINT REFERENCES files(file_id), action VARCHAR(50) NOT NULL, ip_address VARCHAR(45),
  event_time TIMESTAMP NOT NULL, status VARCHAR(20));
CREATE TABLE sessions (
  session_id BIGINT AUTO_INCREMENT PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(user_id),
  jwt_token TEXT NOT NULL, -- SHA-256 hex of the JWT, never the token itself
  login_time TIMESTAMP NOT NULL, expiry_time TIMESTAMP NOT NULL,
  status VARCHAR(20) NOT NULL CHECK (status IN ('ACTIVE','EXPIRED','REVOKED')));
