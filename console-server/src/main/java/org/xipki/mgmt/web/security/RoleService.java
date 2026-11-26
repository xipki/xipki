// License Apache License 2.0

package org.xipki.mgmt.web.security;

import java.util.*;
import org.xipki.mgmt.web.audit.AuditService;
import org.xipki.mgmt.web.core.*;

/**
 * All grants and account mutations serialize on web_authorization_lock, across replicas.
 *
 * @author palos
 */
public class RoleService {
  private final Jdbc jdbc;
  private final Transactions transaction;
  private final RoleCatalog roles;
  private final WebUserDetailsService users;
  private final AuditService audit;

  public RoleService(Jdbc jdbc, Transactions manager, AuditService audit) {
    this.jdbc = jdbc;
    this.transaction = manager;
    this.roles = new RoleCatalog(jdbc);
    this.users = new WebUserDetailsService(jdbc);
    this.audit = audit;
  }

  public List<Map<String, Object>> list() {
    return roles.list().stream().map(this::view).toList();
  }

  private Map<String, Object> view(RoleDefinition role) {
    var result =
        new LinkedHashMap<String, Object>(
            Map.of(
                "name",
                role.name(),
                "displayName",
                role.displayName(),
                "description",
                role.description(),
                "scope",
                role.scope(),
                "builtin",
                role.builtin(),
                "enabled",
                role.enabled(),
                "revision",
                role.revision(),
                "permissions",
                new TreeSet<>(role.permissions()),
                "needsProfiles",
                role.needsProfiles(),
                "userCount",
                roles.userCount(role.name())));
    return result;
  }

  private void requireSuper() {
    var snapshot = AccountService.principal();
    var current = (WebPrincipal) users.loadUserByUsername(snapshot.getUsername());
    if (!current.isEnabled()
        || current.authVersion() != snapshot.authVersion()
        || !current.isSuperAdmin()) {
      throw new AccessDeniedException("Super administrator required");
    }
  }

  /** Creates or updates a role atomically and invalidates users affected by changed grants. */
  public RoleDefinition save(
      String name,
      Long revision,
      String displayName,
      String description,
      String scope,
      boolean enabled,
      List<String> permissionList,
      boolean confirmed) {
    RecentAuthentication.require();
    if (name == null || !name.matches("[A-Z][A-Z0-9_]{1,63}") || "SUPER_ADMIN".equals(name)) {
      throw new RoleValidationException("Reserved or invalid role code");
    }
    if (displayName == null
        || displayName.isBlank()
        || displayName.length() > 128
        || displayName.chars().anyMatch(Character::isISOControl)
        || description == null
        || description.length() > 255
        || description.chars().anyMatch(Character::isISOControl)
        || permissionList == null
        || permissionList.size() > PermissionCatalog.codes().size()
        || permissionList.stream().anyMatch(Objects::isNull)) {
      throw new RoleValidationException("Invalid role fields");
    }
    var permissions = new TreeSet<>(permissionList);
    if (permissions.size() != permissionList.size()) {
      throw new RoleValidationException("Duplicate permissions");
    }
    PermissionCatalog.validate(scope, permissions);
    return transaction.execute(
        status -> {
          jdbc.queryForObject(
              "SELECT id FROM web_authorization_lock WHERE id=1 FOR UPDATE", Integer.class);
          requireSuper();
          RoleDefinition before = null;
          if (revision == null) {
            if (!jdbc.queryForList("SELECT id FROM web_role WHERE name=?", Long.class, name)
                .isEmpty()) {
              throw conflict("Role code already exists or was deleted");
            }
            if (!enabled) {
              throw new RoleValidationException("New role must be enabled");
            }
            if (jdbc.queryForObject(
                    "SELECT COUNT(*) FROM web_role WHERE role_type IS NOT NULL AND builtin=FALSE"
                        + " AND deleted=FALSE",
                    Integer.class)
                >= 100) {
              throw conflict("Custom role limit reached");
            }
          } else {
            before = roles.find(name);
            if (before.deleted() || before.revision() != revision) {
              throw conflict("Role changed; reload before saving");
            }
            if (!before.scope().equals(scope) || before.builtin() && !enabled) {
              throw new RoleValidationException("Built-in role state and role scope cannot change");
            }
          }
          boolean changed =
              before == null
                  || !before.permissions().equals(permissions)
                  || before.enabled() != enabled;
          var previousPermissions = before == null ? Set.<String>of() : before.permissions();
          boolean risk =
              permissions.stream()
                  .anyMatch(
                      p -> !previousPermissions.contains(p) && PermissionCatalog.get(p).highRisk());
          if ((risk || before != null && before.enabled() != enabled) && !confirmed) {
            throw new RoleValidationException("Explicit risk confirmation required");
          }
          if (before == null) {
            jdbc.update(
                "INSERT INTO"
                    + " web_role(name,display_name,description,role_type,builtin,"
                    + "enabled,deleted,revision)"
                    + " VALUES (?,?,?,?,FALSE,TRUE,FALSE,1)",
                name,
                displayName,
                description,
                scope);
          } else {
            jdbc.update(
                "UPDATE web_role SET display_name=?,description=?,enabled=?,revision=revision+1"
                    + " WHERE name=?",
                displayName,
                description,
                enabled,
                name);
          }
          jdbc.update(
              "DELETE FROM web_role_permission WHERE role_id IN (SELECT id FROM web_role WHERE"
                  + " name=?)",
              name);
          for (String permission : permissions) {
            jdbc.update(
                "INSERT INTO web_role_permission(role_id,permission_id) SELECT r.id,p.id FROM"
                    + " web_role r,web_permission p WHERE r.name=? AND p.code=?",
                name,
                permission);
          }
          var affected =
              jdbc.queryForList(
                  "SELECT DISTINCT user_id FROM web_role_binding WHERE role_name=?",
                  Long.class,
                  name);
          for (long id : affected) {
            AccountService.validateSeparation(users.bindings(id));
            if (changed) {
              invalidate(id);
            }
          }
          var after = roles.find(name);
          audit.authorizationChange(
              before == null ? "ROLE_CREATE" : "ROLE_UPDATE", "role", name, before, after);
          return after;
        });
  }

  public void delete(String name, long revision) {
    RecentAuthentication.require();
    transaction.executeWithoutResult(
        status -> {
          jdbc.queryForObject(
              "SELECT id FROM web_authorization_lock WHERE id=1 FOR UPDATE", Integer.class);
          requireSuper();
          var role = roles.find(name);
          if (role.builtin()) {
            throw new RoleValidationException("Built-in roles cannot be deleted");
          }
          if (role.deleted() || role.revision() != revision) {
            throw conflict("Role changed; reload before deleting");
          }
          if (roles.userCount(name) > 0) {
            throw conflict("Role is assigned; remove user grants before deleting");
          }
          jdbc.update(
              "UPDATE web_role SET deleted=TRUE,enabled=FALSE,revision=revision+1 WHERE name=?",
              name);
          audit.authorizationChange("ROLE_DELETE", "role", name, role, roles.find(name));
        });
  }

  private void invalidate(long id) {
    jdbc.update("UPDATE web_user SET auth_version=auth_version+1 WHERE id=?", id);
    jdbc.update("DELETE FROM lite_session WHERE user_id=?", id);
  }

  private static ApiException conflict(String reason) {
    return new ApiException(409, reason);
  }
}
