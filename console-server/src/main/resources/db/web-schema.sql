CREATE TABLE IF NOT EXISTS web_schema_version (
  version INT NOT NULL PRIMARY KEY,
  applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS web_user (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(128) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  display_name VARCHAR(255) NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  last_login_at TIMESTAMP NULL,
  auth_version BIGINT NOT NULL DEFAULT 1,
  password_change_required BOOLEAN NOT NULL DEFAULT FALSE,
  reset_allowed_at TIMESTAMP(3) NULL
);

CREATE TABLE IF NOT EXISTS web_role (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(64) NOT NULL UNIQUE,
  description VARCHAR(255) NOT NULL,
  display_name VARCHAR(128) NULL,
  role_type VARCHAR(16) NULL,
  builtin BOOLEAN NOT NULL DEFAULT FALSE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  deleted BOOLEAN NOT NULL DEFAULT FALSE,
  revision BIGINT NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS web_permission (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  code VARCHAR(128) NOT NULL UNIQUE,
  description VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS web_role_permission (
  role_id BIGINT NOT NULL,
  permission_id BIGINT NOT NULL,
  PRIMARY KEY (role_id, permission_id),
  CONSTRAINT fk_web_role_permission_role FOREIGN KEY (role_id) REFERENCES web_role(id),
  CONSTRAINT fk_web_role_permission_permission FOREIGN KEY (permission_id) REFERENCES web_permission(id)
);

CREATE TABLE IF NOT EXISTS web_audit_event (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  event_time TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  actor_user_id BIGINT NULL,
  actor_username VARCHAR(128) NULL,
  source_ip VARCHAR(64) NULL,
  request_id VARCHAR(128) NULL,
  http_method VARCHAR(16) NULL,
  request_path VARCHAR(512) NULL,
  resource_type VARCHAR(128) NULL,
  resource_id VARCHAR(255) NULL,
  action VARCHAR(128) NOT NULL,
  result VARCHAR(32) NOT NULL,
  failure_category VARCHAR(128) NULL,
  duration_ms BIGINT NULL,
  details_json TEXT NULL,
  permission_codes TEXT NULL,
  INDEX ix_web_audit_time (event_time),
  INDEX ix_web_audit_actor (actor_user_id, event_time),
  INDEX ix_web_audit_action (action, result, event_time)
);

CREATE TABLE IF NOT EXISTS web_authorization_lock (
  id INT NOT NULL PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS web_role_binding (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT NOT NULL,
  role_name VARCHAR(64) NOT NULL,
  scope_type VARCHAR(32) NOT NULL,
  ca_name VARCHAR(128) NULL,
  ca_fingerprint CHAR(64) NULL,
  all_profiles BOOLEAN NOT NULL DEFAULT FALSE,
  CONSTRAINT fk_web_binding_user FOREIGN KEY (user_id) REFERENCES web_user(id),
  INDEX ix_web_binding_user (user_id),
  INDEX ix_web_binding_ca (ca_name)
);

CREATE TABLE IF NOT EXISTS web_binding_profile (
  binding_id BIGINT NOT NULL,
  profile_name VARCHAR(128) NOT NULL,
  PRIMARY KEY (binding_id, profile_name),
  CONSTRAINT fk_web_binding_profile FOREIGN KEY (binding_id) REFERENCES web_role_binding(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS web_certificate_owner (
  ca_name VARCHAR(128) NOT NULL,
  ca_fingerprint CHAR(64) NOT NULL,
  serial_number VARCHAR(160) NOT NULL,
  user_id BIGINT NOT NULL,
  profile_name VARCHAR(128) NOT NULL,
  issued_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (ca_name, ca_fingerprint, serial_number),
  INDEX ix_web_owner (user_id, ca_name, issued_at),
  CONSTRAINT fk_web_owner_user FOREIGN KEY (user_id) REFERENCES web_user(id)
);

CREATE TABLE IF NOT EXISTS web_login_throttle (
  throttle_key CHAR(64) NOT NULL PRIMARY KEY,
  attempts INT NOT NULL DEFAULT 0,
  window_start TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
);

CREATE TABLE IF NOT EXISTS web_ca_enrollment (
  operation_id CHAR(36) NOT NULL PRIMARY KEY,
  owner_id BIGINT NOT NULL,
  idempotency_key VARCHAR(128) NOT NULL,
  request_hash CHAR(64) NOT NULL,
  purpose VARCHAR(24) NOT NULL,
  status VARCHAR(32) NOT NULL,
  version BIGINT NOT NULL DEFAULT 0,
  public_json MEDIUMTEXT NOT NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY enrollment_idempotency (owner_id, idempotency_key),
  KEY enrollment_owner (owner_id, status)
);

CREATE TABLE IF NOT EXISTS lite_session (
  token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  auth_version BIGINT NOT NULL DEFAULT 0,
  csrf_token CHAR(43) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  created_ms BIGINT NOT NULL,
  last_access_ms BIGINT NOT NULL,
  recent_auth_ms BIGINT NOT NULL DEFAULT 0,
  INDEX lite_session_expiry(last_access_ms),
  INDEX lite_session_user(user_id),
  CONSTRAINT lite_session_user_fk FOREIGN KEY(user_id) REFERENCES web_user(id) ON DELETE CASCADE
) ENGINE=InnoDB;
