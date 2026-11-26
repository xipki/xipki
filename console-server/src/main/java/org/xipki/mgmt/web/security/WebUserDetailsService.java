// License Apache License 2.0

package org.xipki.mgmt.web.security;

import java.util.List;
import org.xipki.mgmt.web.core.*;

/**
 * @author palos
 */
public final class WebUserDetailsService {
  private final Jdbc jdbcTemplate;
  private final RoleCatalog roles;

  public WebUserDetailsService(Jdbc jdbcTemplate) {
    this.jdbcTemplate = jdbcTemplate;
    this.roles = new RoleCatalog(jdbcTemplate);
  }

  public WebPrincipal loadUserByUsername(String username) {
    var rows =
        jdbcTemplate.query(
            "SELECT"
                + " id,username,password_hash,enabled,display_name,auth_version,"
                + "password_change_required"
                + " FROM web_user WHERE username=?",
            (rs, n) ->
                new WebPrincipal(
                    rs.getLong("id"),
                    rs.getString("username"),
                    rs.getString("password_hash"),
                    rs.getBoolean("enabled"),
                    rs.getString("display_name"),
                    rs.getLong("auth_version"),
                    rs.getBoolean("password_change_required"),
                    bindings(rs.getLong("id"))),
            username);
    if (rows.isEmpty()) {
      throw new ApiException(401, "Invalid credentials");
    }
    return rows.get(0);
  }

  public List<RoleBinding> bindings(long userId) {
    return jdbcTemplate.query(
        "SELECT id,role_name,scope_type,ca_name,ca_fingerprint,all_profiles FROM web_role_binding"
            + " WHERE user_id=? ORDER BY id",
        (rs, n) ->
            new RoleBinding(
                rs.getString("role_name"),
                rs.getString("scope_type"),
                rs.getString("ca_name"),
                rs.getString("ca_fingerprint"),
                rs.getBoolean("all_profiles"),
                jdbcTemplate.queryForList(
                    "SELECT profile_name FROM web_binding_profile WHERE binding_id=? ORDER BY"
                        + " profile_name",
                    String.class,
                    rs.getLong("id")),
                roles.find(rs.getString("role_name"))),
        userId);
  }
}
