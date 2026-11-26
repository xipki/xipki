// License Apache License 2.0

package org.xipki.mgmt.web.security;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.xipki.mgmt.web.audit.AuditService;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.security.PermissionCatalog.Permission;

/**
 * @author palos
 */
public class AccountService {
  private final Jdbc jdbc;
  private final Password encoder;
  private final WebUserDetailsService users;
  private final AuditService audit;
  private final Transactions transaction;
  private final SecureRandom random = new SecureRandom();

  public AccountService(
      Jdbc jdbc,
      Password encoder,
      WebUserDetailsService users,
      AuditService audit,
      Transactions manager) {
    this.jdbc = jdbc;
    this.encoder = encoder;
    this.users = users;
    this.audit = audit;
    this.transaction = manager;
  }

  public static WebPrincipal principal() {
    var principal = RequestContext.principal();
    if (principal == null) {
      throw new AccessDeniedException("Database identity required");
    }
    return principal;
  }

  public RoleBinding resolveBinding(
      String role,
      String scope,
      String ca,
      String fingerprint,
      boolean allProfiles,
      List<String> profiles) {
    return new RoleBinding(
        role, scope, ca, fingerprint, allProfiles, profiles, new RoleCatalog(jdbc).find(role));
  }

  private WebPrincipal currentActor() {
    var actor = principal();
    var fresh = (WebPrincipal) users.loadUserByUsername(actor.getUsername());
    if (!fresh.isEnabled() || fresh.authVersion() != actor.authVersion()) {
      throw new AccessDeniedException("Authorization changed");
    }
    return fresh;
  }

  private WebPrincipal requirePermission(String permission) {
    var actor = currentActor();
    if (!actor.isSuperAdmin()
        && actor.bindings().stream()
            .noneMatch(
                b ->
                    b.scope().equals("PLATFORM")
                        && b.definition().active()
                        && b.definition().permissions().contains(permission))) {
      throw new AccessDeniedException("Permission denied");
    }
    if (PermissionCatalog.get(permission).recentAuthRequired()) {
      RecentAuthentication.require();
    }
    return actor;
  }

  private <T> T locked(Supplier<T> work) {
    return transaction.execute(
        status -> {
          jdbc.queryForObject(
              "SELECT id FROM web_authorization_lock WHERE id=1 FOR UPDATE", Integer.class);
          return work.get();
        });
  }

  private void manageable(WebPrincipal actor, long id) {
    if (!actor.isSuperAdmin()
        && users.bindings(id).stream().anyMatch(b -> b.definition().privileged())) {
      throw new AccessDeniedException("Permission denied");
    }
  }

  private Map<String, Object> view(long id) {
    var rows =
        jdbc.queryForList(
            "SELECT"
                + " id,username,display_name,enabled,password_change_required,"
                + "created_at,last_login_at"
                + " FROM web_user WHERE id=?",
            id);
    if (rows.isEmpty()) {
      throw new ApiException(404, "Request rejected");
    }
    var row = rows.get(0);
    var result = new LinkedHashMap<String, Object>();
    result.put("id", row.get("id"));
    result.put("username", row.get("username"));
    result.put("displayName", row.get("display_name"));
    result.put("enabled", row.get("enabled"));
    result.put("passwordChangeRequired", row.get("password_change_required"));
    result.put("createdAt", row.get("created_at"));
    result.put("lastLoginAt", row.get("last_login_at"));
    result.put("bindings", users.bindings(id));
    return result;
  }

  public Map<String, Object> get(long id) {
    var actor = requirePermission("USER_READ");
    manageable(actor, id);
    return view(id);
  }

  public Map<String, Object> list(String search, int page, int size) {
    var actor = requirePermission("USER_READ");
    if (page < 0 || size < 1 || size > 100 || (search != null && search.length() > 128)) {
      throw new IllegalArgumentException("Invalid query");
    }
    String sql = "SELECT u.id FROM web_user u WHERE LOCATE(?,u.username)>0";
    if (!actor.isSuperAdmin()) {
      String privileged =
          PermissionCatalog.entries().stream()
              .filter(Permission::privileged)
              .map(p -> "'" + p.code() + "'")
              .collect(Collectors.joining(","));
      sql +=
          " AND NOT EXISTS (SELECT 1 FROM web_role_binding b JOIN web_role r ON r.name=b.role_name"
              + " LEFT JOIN web_role_permission rp ON rp.role_id=r.id LEFT JOIN web_permission p ON"
              + " p.id=rp.permission_id WHERE b.user_id=u.id AND (b.role_name='SUPER_ADMIN' OR"
              + " p.code IN ("
              + privileged
              + ")))";
    }
    var ids =
        jdbc.queryForList(
            sql + " ORDER BY u.id LIMIT ? OFFSET ?",
            Long.class,
            search == null ? "" : search,
            size + 1,
            (long) page * size);
    return Map.of(
        "items",
        ids.stream().limit(size).map(this::view).toList(),
        "hasMore",
        ids.size() > size,
        "page",
        page,
        "size",
        size);
  }

  public Map<String, Object> create(String username, String displayName) {
    if (username == null || !username.matches("[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,63}")) {
      throw new IllegalArgumentException("Invalid username");
    }
    checkDisplayName(displayName);
    return locked(
        () -> {
          requirePermission("USER_CREATE");
          String password = temporaryPassword();
          jdbc.update(
              "INSERT INTO web_user(username,password_hash,display_name,password_change_required)"
                  + " VALUES (?,?,?,TRUE)",
              username,
              encoder.encode(password),
              displayName);
          long id =
              jdbc.queryForObject("SELECT id FROM web_user WHERE username=?", Long.class, username);
          var result = view(id);
          audit.identityChange("USER_CREATE", id, null, result);
          result.put("temporaryPassword", password);
          return result;
        });
  }

  public void update(long id, String displayName) {
    checkDisplayName(displayName);
    locked(
        () -> {
          var actor = requirePermission("USER_UPDATE");
          manageable(actor, id);
          var before = view(id);
          jdbc.update("UPDATE web_user SET display_name=? WHERE id=?", displayName, id);
          audit.identityChange("USER_UPDATE", id, before, view(id));
          return null;
        });
  }

  public String currentDisplayName() {
    // Session principals are immutable snapshots; profile edits must be visible to every session.
    return jdbc.queryForObject(
        "SELECT display_name FROM web_user WHERE id=?", String.class, principal().id());
  }

  public void updateOwnProfile(String displayName) {
    checkDisplayName(displayName);
    locked(
        () -> {
          var actor = currentActor();
          if (actor.passwordChangeRequired()) {
            throw new AccessDeniedException("Password change required");
          }
          jdbc.update("UPDATE web_user SET display_name=? WHERE id=?", displayName, actor.id());
          audit.identityChange(
              "PROFILE_UPDATE",
              actor.id(),
              Collections.singletonMap("displayName", actor.displayName()),
              Collections.singletonMap("displayName", displayName));
          return null;
        });
  }

  public void setEnabled(long id, boolean enabled) {
    locked(
        () -> {
          var actor = requirePermission("USER_STATUS_UPDATE");
          manageable(actor, id);
          var before = view(id);
          jdbc.update("UPDATE web_user SET enabled=? WHERE id=?", enabled, id);
          protectLastSuper();
          invalidate(id);
          audit.identityChange(enabled ? "USER_ENABLE" : "USER_DISABLE", id, before, view(id));
          return null;
        });
  }

  /** Replaces an account password with a one-time value and rate-limits repeated resets. */
  public String resetPassword(long id) {
    RecentAuthentication.require();
    return locked(
        () -> {
          var actor = requirePermission("USER_PASSWORD_RESET");
          manageable(actor, id);
          view(id);
          Integer allowed =
              jdbc.queryForObject(
                  "SELECT reset_allowed_at IS NULL OR reset_allowed_at<=CURRENT_TIMESTAMP(3) FROM"
                      + " web_user WHERE id=?",
                  Integer.class,
                  id);
          if (allowed == null || allowed != 1) {
            throw new ApiException(429, "Request rejected");
          }
          String password = temporaryPassword();
          jdbc.update(
              "UPDATE web_user SET"
                  + " password_hash=?,password_change_required=TRUE,"
                  + "reset_allowed_at=?"
                  + " WHERE id=?",
              encoder.encode(password),
              java.time.Instant.now().plusSeconds(60),
              id);
          invalidate(id);
          audit.identityChange("PASSWORD_RESET", id, null, Map.of("passwordChangeRequired", true));
          return password;
        });
  }

  public void revokeSessions(long id) {
    locked(
        () -> {
          var actor = requirePermission("USER_SESSION_REVOKE");
          manageable(actor, id);
          view(id);
          invalidate(id);
          audit.identityChange("SESSIONS_REVOKE", id, null, null);
          return null;
        });
  }

  public void replaceBindings(long id, List<RoleBinding> bindings) {
    RecentAuthentication.require();
    if (bindings == null
        || bindings.size() > 100
        || new HashSet<>(bindings).size() != bindings.size()) {
      throw new IllegalArgumentException("Invalid bindings");
    }
    locked(
        () -> {
          if (!currentActor().isSuperAdmin()) {
            throw new AccessDeniedException("Permission denied");
          }
          var previous = users.bindings(id);
          var fresh =
              bindings.stream()
                  .map(
                      b ->
                          resolveBinding(
                              b.role(),
                              b.scope(),
                              b.caName(),
                              b.caFingerprint(),
                              b.allProfiles(),
                              b.profiles()))
                  .toList();
          for (var binding : fresh) {
            if (!binding.definition().active()
                && previous.stream().noneMatch(p -> sameGrant(p, binding))) {
              throw new IllegalArgumentException("Disabled roles cannot receive new grants");
            }
          }
          if (new HashSet<>(fresh).size() != fresh.size()) {
            throw new IllegalArgumentException("Duplicate grants");
          }
          validateSeparation(fresh);
          var before = view(id);
          jdbc.update("DELETE FROM web_role_binding WHERE user_id=?", id);
          for (var binding : fresh) {
            long bindingId =
                jdbc.insert(
                    "INSERT INTO"
                        + " web_role_binding(user_id,role_name,scope_type,ca_name,"
                        + "ca_fingerprint,all_profiles)"
                        + " VALUES (?,?,?,?,?,?)",
                    id,
                    binding.role(),
                    binding.scope(),
                    binding.caName(),
                    binding.caFingerprint(),
                    binding.allProfiles());
            for (String profile : new LinkedHashSet<>(binding.profiles())) {
              jdbc.update("INSERT INTO web_binding_profile VALUES (?,?)", bindingId, profile);
            }
          }
          protectLastSuper();
          invalidate(id);
          audit.identityChange("ROLE_BINDINGS_REPLACE", id, before, view(id));
          return null;
        });
  }

  private static boolean sameGrant(RoleBinding a, RoleBinding b) {
    return a.role().equals(b.role())
        && a.scope().equals(b.scope())
        && Objects.equals(a.caName(), b.caName())
        && Objects.equals(a.caFingerprint(), b.caFingerprint())
        && a.allProfiles() == b.allProfiles()
        && new HashSet<>(a.profiles()).equals(new HashSet<>(b.profiles()));
  }

  public static void validateSeparation(List<RoleBinding> bindings) {
    var permissions = new HashSet<String>();
    bindings.forEach(b -> permissions.addAll(b.globalPermissions()));
    boolean superAdmin =
        bindings.stream().anyMatch(b -> "SUPER_ADMIN".equals(b.role()) && b.definition().active());
    PermissionCatalog.validateSeparation(permissions, superAdmin);
  }

  public void changePassword(String currentPassword, String newPassword) {
    validatePassword(newPassword);
    locked(
        () -> {
          var actor = currentActor();
          verifyPassword(actor, currentPassword);
          if (encoder.matches(newPassword, actor.getPassword())) {
            throw new IllegalArgumentException("Password must change");
          }
          jdbc.update(
              "UPDATE web_user SET password_hash=?,password_change_required=FALSE WHERE id=?",
              encoder.encode(newPassword),
              actor.id());
          invalidate(actor.id());
          audit.identityChange("PASSWORD_CHANGE", actor.id(), null, null);
          return null;
        });
  }

  public void reauthenticate(String password) {
    verifyPassword(currentActor(), password);
  }

  /**
   * Rehash a verified legacy credential without invalidating sessions or changing account flags.
   */
  public WebPrincipal upgradePasswordAfterLogin(WebPrincipal user, String password) {
    if (!encoder.needsUpgrade(user.getPassword())) {
      return user;
    }
    if (!encoder.matches(password, user.getPassword())) {
      throw new ApiException(401, "Invalid credentials");
    }
    String upgraded = encoder.encode(password);
    return transaction.execute(
        status -> {
          var ids =
              jdbc.queryForList(
                  "SELECT id FROM web_user WHERE id=? AND enabled=TRUE AND auth_version=? FOR"
                      + " UPDATE",
                  Long.class,
                  user.id(),
                  user.authVersion());
          if (ids.isEmpty()) {
            throw new ApiException(401, "Invalid credentials");
          }
          var fresh = users.loadUserByUsername(user.getUsername());
          if (user.getPassword().equals(fresh.getPassword())) {
            jdbc.update(
                "UPDATE web_user SET password_hash=? WHERE id=? AND password_hash=?",
                upgraded,
                user.id(),
                user.getPassword());
            return users.loadUserByUsername(user.getUsername());
          }
          // Another successful login may already have upgraded the same credential.
          if (!encoder.matches(password, fresh.getPassword())) {
            throw new ApiException(401, "Invalid credentials");
          }
          return fresh;
        });
  }

  public void recordLogin(WebPrincipal user) {
    jdbc.update("UPDATE web_user SET last_login_at=CURRENT_TIMESTAMP WHERE id=?", user.id());
  }

  private void requireCaDeletion(String name, String fingerprint) {
    if (currentActor().bindings().stream()
        .noneMatch(b -> b.allows("CA_DELETE", name, fingerprint, null))) {
      throw new AccessDeniedException("Permission denied");
    }
  }

  public long caBindingCount(String name, String fingerprint) {
    requireCaDeletion(name, fingerprint);
    return jdbc.queryForObject(
        "SELECT COUNT(*) FROM web_role_binding WHERE ca_name=?", Long.class, name);
  }

  public void revokeCaBindings(String name, String fingerprint) {
    locked(
        () -> {
          requireCaDeletion(name, fingerprint);
          var ids =
              jdbc.queryForList(
                  "SELECT DISTINCT user_id FROM web_role_binding WHERE ca_name=?",
                  Long.class,
                  name);
          for (long id : ids) {
            var before = view(id);
            jdbc.update("DELETE FROM web_role_binding WHERE user_id=? AND ca_name=?", id, name);
            invalidate(id);
            audit.identityChange("CA_BINDINGS_INVALIDATE", id, before, view(id));
          }
          return null;
        });
  }

  private void verifyPassword(WebPrincipal actor, String password) {
    if (password == null
        || password.getBytes(StandardCharsets.UTF_8).length > 72
        || !encoder.matches(password, actor.getPassword())) {
      throw new AccessDeniedException("Invalid credentials");
    }
  }

  public static void validatePassword(String password) {
    if (password == null
        || password.codePointCount(0, password.length()) < 15
        || password.getBytes(StandardCharsets.UTF_8).length > 72
        || password.indexOf('\0') >= 0
        || password.indexOf('\n') >= 0
        || password.indexOf('\r') >= 0) {
      throw new IllegalArgumentException(
          "Password must contain at least 15 characters and at most 72 UTF-8 bytes");
    }
  }

  private void invalidate(long id) {
    jdbc.update("UPDATE web_user SET auth_version=auth_version+1 WHERE id=?", id);
    jdbc.update("DELETE FROM lite_session WHERE user_id=?", id);
  }

  private void protectLastSuper() {
    Integer count =
        jdbc.queryForObject(
            "SELECT COUNT(DISTINCT u.id) FROM web_user u JOIN web_role_binding b ON b.user_id=u.id"
                + " WHERE u.enabled=TRUE AND b.role_name='SUPER_ADMIN'",
            Integer.class);
    if (count == null || count < 1) {
      throw new IllegalArgumentException("At least one enabled super administrator is required");
    }
  }

  private String temporaryPassword() {
    byte[] bytes = new byte[24];
    random.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private static void checkDisplayName(String name) {
    if (name != null && (name.length() > 128 || name.chars().anyMatch(Character::isISOControl))) {
      throw new IllegalArgumentException("Invalid display name");
    }
  }
}
