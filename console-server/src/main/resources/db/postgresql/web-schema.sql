CREATE TABLE web_schema_version (
  version INT NOT NULL PRIMARY KEY,
  applied_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE web_user (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(128) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  display_name VARCHAR(255),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login_at TIMESTAMP(3),
  auth_version BIGINT NOT NULL DEFAULT 1,
  password_change_required BOOLEAN NOT NULL DEFAULT FALSE,
  reset_allowed_at TIMESTAMP(3)
);

CREATE TABLE web_role (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(64) NOT NULL UNIQUE,
  description VARCHAR(255) NOT NULL,
  display_name VARCHAR(128),
  role_type VARCHAR(16),
  builtin BOOLEAN NOT NULL DEFAULT FALSE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  deleted BOOLEAN NOT NULL DEFAULT FALSE,
  revision BIGINT NOT NULL DEFAULT 1
);

CREATE TABLE web_permission (
  id BIGSERIAL PRIMARY KEY,
  code VARCHAR(128) NOT NULL UNIQUE,
  description VARCHAR(255) NOT NULL
);

CREATE TABLE web_role_permission (
  role_id BIGINT NOT NULL REFERENCES web_role(id),
  permission_id BIGINT NOT NULL REFERENCES web_permission(id),
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE web_audit_event (
  id BIGSERIAL PRIMARY KEY,
  event_time TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  actor_user_id BIGINT,
  actor_username VARCHAR(128),
  source_ip VARCHAR(64),
  request_id VARCHAR(128),
  http_method VARCHAR(16),
  request_path VARCHAR(512),
  resource_type VARCHAR(128),
  resource_id VARCHAR(255),
  action VARCHAR(128) NOT NULL,
  result VARCHAR(32) NOT NULL,
  failure_category VARCHAR(128),
  duration_ms BIGINT,
  details_json TEXT,
  permission_codes TEXT
);
CREATE INDEX ix_web_audit_time ON web_audit_event(event_time);
CREATE INDEX ix_web_audit_actor ON web_audit_event(actor_user_id, event_time);
CREATE INDEX ix_web_audit_action ON web_audit_event(action, result, event_time);

CREATE TABLE web_authorization_lock (id INT PRIMARY KEY);

CREATE TABLE web_role_binding (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES web_user(id),
  role_name VARCHAR(64) NOT NULL,
  scope_type VARCHAR(32) NOT NULL,
  ca_name VARCHAR(128),
  ca_fingerprint CHAR(64),
  all_profiles BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX ix_web_binding_user ON web_role_binding(user_id);
CREATE INDEX ix_web_binding_ca ON web_role_binding(ca_name);

CREATE TABLE web_binding_profile (
  binding_id BIGINT NOT NULL REFERENCES web_role_binding(id) ON DELETE CASCADE,
  profile_name VARCHAR(128) NOT NULL,
  PRIMARY KEY (binding_id, profile_name)
);

CREATE TABLE web_certificate_owner (
  ca_name VARCHAR(128) NOT NULL,
  ca_fingerprint CHAR(64) NOT NULL,
  serial_number VARCHAR(160) NOT NULL,
  user_id BIGINT NOT NULL REFERENCES web_user(id),
  profile_name VARCHAR(128) NOT NULL,
  issued_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (ca_name, ca_fingerprint, serial_number)
);
CREATE INDEX ix_web_owner ON web_certificate_owner(user_id, ca_name, issued_at);

CREATE TABLE web_login_throttle (
  throttle_key CHAR(64) PRIMARY KEY,
  attempts INT NOT NULL DEFAULT 0,
  window_start TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE web_ca_enrollment (
  operation_id CHAR(36) PRIMARY KEY,
  owner_id BIGINT NOT NULL,
  idempotency_key VARCHAR(128) NOT NULL,
  request_hash CHAR(64) NOT NULL,
  purpose VARCHAR(24) NOT NULL,
  status VARCHAR(32) NOT NULL,
  version BIGINT NOT NULL DEFAULT 0,
  public_json TEXT NOT NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (owner_id, idempotency_key)
);
CREATE INDEX enrollment_owner ON web_ca_enrollment(owner_id, status);

CREATE TABLE lite_session (
  token_hash CHAR(64) PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES web_user(id) ON DELETE CASCADE,
  auth_version BIGINT NOT NULL DEFAULT 0,
  csrf_token CHAR(43) NOT NULL,
  created_ms BIGINT NOT NULL,
  last_access_ms BIGINT NOT NULL,
  recent_auth_ms BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX lite_session_expiry ON lite_session(last_access_ms);
CREATE INDEX lite_session_user ON lite_session(user_id);
