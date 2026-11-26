// License Apache License 2.0

package org.xipki.mgmt.web.security;

import java.util.*;
import org.xipki.mgmt.web.core.*;

/**
 * No process-local cache: committed database definitions are the source of authority.
 *
 * @author palos
 */
public class RoleCatalog {
  private final Jdbc jdbc;

  public RoleCatalog(Jdbc jdbc) {
    this.jdbc = jdbc;
  }

  public RoleDefinition find(String name) {
    var rows =
        jdbc.query(
            "SELECT"
                + " id,name,display_name,description,role_type,builtin,enabled,deleted,"
                + "revision"
                + " FROM web_role WHERE name=? AND role_type IS NOT NULL",
            (rs, n) -> {
              var permissions =
                  new TreeSet<>(
                      jdbc.queryForList(
                          "SELECT p.code FROM web_role_permission rp JOIN web_permission p ON"
                              + " p.id=rp.permission_id WHERE rp.role_id=?",
                          String.class,
                          rs.getLong("id")));
              permissions.forEach(PermissionCatalog::get);
              // Recovery authority is reserved; editable roles always use persisted grants.
              if ("SUPER_ADMIN".equals(rs.getString("name"))) {
                permissions = new TreeSet<>(PermissionCatalog.codes());
              }
              return new RoleDefinition(
                  rs.getString("name"),
                  rs.getString("display_name"),
                  rs.getString("description"),
                  rs.getString("role_type"),
                  rs.getBoolean("builtin"),
                  rs.getBoolean("enabled"),
                  rs.getBoolean("deleted"),
                  rs.getLong("revision"),
                  permissions);
            },
            name);
    if (rows.isEmpty()) {
      throw new ApiException(404, "Role not found");
    }
    return rows.get(0);
  }

  public List<RoleDefinition> list() {
    return jdbc
        .queryForList(
            "SELECT name FROM web_role WHERE role_type IS NOT NULL AND deleted=FALSE ORDER BY"
                + " builtin DESC,id",
            String.class)
        .stream()
        .map(this::find)
        .toList();
  }

  public long userCount(String name) {
    return jdbc.queryForObject(
        "SELECT COUNT(DISTINCT user_id) FROM web_role_binding WHERE role_name=?", Long.class, name);
  }
}
