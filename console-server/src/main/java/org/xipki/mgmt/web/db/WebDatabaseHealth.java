// License Apache License 2.0

package org.xipki.mgmt.web.db;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;
import java.util.Set;
import org.xipki.mgmt.web.core.Jdbc;
import org.xipki.mgmt.web.core.Jdbc.DataAccessException;

/** Performs non-mutating readiness checks against the current Console schema. */
public final class WebDatabaseHealth {
  static final Set<String> TABLES =
      Set.of(
          "web_schema_version",
          "web_user",
          "web_role",
          "web_permission",
          "web_role_permission",
          "web_audit_event",
          "web_authorization_lock",
          "web_role_binding",
          "web_binding_profile",
          "web_certificate_owner",
          "web_login_throttle",
          "web_ca_enrollment",
          "lite_session");

  private static final Map<String, String> REQUIRED_COLUMNS =
      Map.ofEntries(
          Map.entry("web_schema_version", "version,applied_at"),
          Map.entry(
              "web_user",
              "id,username,password_hash,display_name,enabled,created_at,updated_at,last_login_at,"
                  + "auth_version,password_change_required,reset_allowed_at"),
          Map.entry(
              "web_role",
              "id,name,description,display_name,role_type,builtin,enabled,deleted,revision"),
          Map.entry("web_permission", "id,code,description"),
          Map.entry("web_role_permission", "role_id,permission_id"),
          Map.entry(
              "web_audit_event",
              "id,event_time,actor_user_id,actor_username,source_ip,request_id,http_method,"
                  + "request_path,resource_type,resource_id,action,result,failure_category,"
                  + "duration_ms,details_json,permission_codes"),
          Map.entry("web_authorization_lock", "id"),
          Map.entry(
              "web_role_binding",
              "id,user_id,role_name,scope_type,ca_name,ca_fingerprint,all_profiles"),
          Map.entry("web_binding_profile", "binding_id,profile_name"),
          Map.entry(
              "web_certificate_owner",
              "ca_name,ca_fingerprint,serial_number,user_id,profile_name,issued_at"),
          Map.entry("web_login_throttle", "throttle_key,attempts,window_start"),
          Map.entry(
              "web_ca_enrollment",
              "operation_id,owner_id,idempotency_key,request_hash,purpose,status,version,"
                  + "public_json,created_at,updated_at"),
          Map.entry(
              "lite_session",
              "token_hash,user_id,auth_version,csrf_token,created_ms,last_access_ms,recent_auth_ms"));

  private final Jdbc jdbcTemplate;

  public WebDatabaseHealth(Jdbc jdbcTemplate) {
    this.jdbcTemplate = jdbcTemplate;
  }

  /** Returns whether the configured database exposes the complete current schema. */
  public boolean isReady() {
    try {
      return Boolean.TRUE.equals(
          jdbcTemplate.connection(
              connection -> {
                verify(connection);
                return true;
              }));
    } catch (DataAccessException ex) {
      return false;
    }
  }

  /** Verifies the schema version and every table column consumed by the application. */
  static void verify(Connection connection) throws SQLException {
    try (Statement statement = connection.createStatement()) {
      statement.setQueryTimeout(5);
      try (ResultSet result =
          statement.executeQuery(
              "SELECT COUNT(*), MIN(version), MAX(version) FROM web_schema_version")) {
        if (!result.next()
            || result.getInt(1) != 1
            || result.getInt(2) != 6
            || result.getInt(3) != 6) {
          throw new SQLException("Unsupported Web schema version");
        }
      }
      for (var entry : REQUIRED_COLUMNS.entrySet()) {
        try (ResultSet ignored =
            statement.executeQuery(
                "SELECT " + entry.getValue() + " FROM " + entry.getKey() + " WHERE 1=0")) {
          // Preparing each projection catches missing or renamed columns without changing data.
        }
      }
    }
  }
}
