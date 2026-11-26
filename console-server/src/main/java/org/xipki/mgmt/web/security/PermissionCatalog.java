// License Apache License 2.0

package org.xipki.mgmt.web.security;

import java.util.*;
import org.xipki.mgmt.web.core.*;

/**
 * Operations implemented by the server, not role grants. Grants live in MariaDB.
 *
 * @author palos
 */
public final class PermissionCatalog {
  public record Permission(
      String code,
      String scope,
      String group,
      Set<String> dependencies,
      boolean readOnly,
      boolean privileged,
      boolean highRisk,
      boolean profileRequired,
      boolean allCasOnly,
      boolean reserved,
      boolean recentAuthRequired,
      boolean auditCompatible) {}

  private static final Map<String, Permission> ENTRIES;
  public static final Set<String> ISSUANCE =
      Set.of("CERT_ISSUE", "CERT_KEYGEN", "CERT_CROSS", "CA_ISSUE_SUBCA");
  public static final Set<String> AUDIT =
      Set.of("AUDIT_READ", "AUDIT_EXPORT", "AUDIT_CONTEXT_READ");

  static {
    var entries = new LinkedHashMap<String, Permission>();
    add(entries, "ROLE_READ", "PLATFORM", "Users", true, false, false);
    add(entries, "ROLE_MANAGE", "PLATFORM", "Users", false, true, true, "ROLE_READ");
    add(entries, "USER_ROLE_ASSIGN", "PLATFORM", "Users", false, true, true, "ROLE_READ");
    add(entries, "USER_READ", "PLATFORM", "Users", true, false, false);
    for (String action :
        List.of("CREATE", "UPDATE", "STATUS_UPDATE", "PASSWORD_RESET", "SESSION_REVOKE")) {
      add(entries, "USER_" + action, "PLATFORM", "Users", false, true, false, "USER_READ");
    }
    for (String resource : List.of("SIGNER", "REQUESTOR", "PUBLISHER", "PROFILE", "KEYPAIRGEN")) {
      add(entries, resource + "_READ", "PLATFORM", resource, true, false, false);
      if (resource.equals("PROFILE")) {
        add(
            entries,
            "PROFILE_CONFIG_READ",
            "PLATFORM",
            resource,
            true,
            true,
            false,
            "PROFILE_READ");
      }
      for (String action : List.of("CREATE", "UPDATE", "DELETE")) {
        add(
            entries,
            resource + "_" + action,
            "PLATFORM",
            resource,
            false,
            true,
            true,
            resource.equals("PROFILE") && action.equals("UPDATE")
                ? "PROFILE_CONFIG_READ"
                : resource + "_READ");
      }
    }
    add(entries, "CA_CREATE_ROOT", "PLATFORM", "New CA", false, true, true);
    add(entries, "CA_IMPORT", "PLATFORM", "New CA", false, true, true);
    add(entries, "AUDIT_READ", "PLATFORM", "Audit", true, true, false);
    add(entries, "AUDIT_EXPORT", "PLATFORM", "Audit", true, true, false, "AUDIT_READ");
    add(
        entries,
        "AUDIT_CONTEXT_READ",
        "PLATFORM",
        "Audit",
        true,
        true,
        false,
        "AUDIT_READ",
        "ROLE_READ");
    add(entries, "SYSTEM_READ", "PLATFORM", "System", true, false, false);
    for (String code : List.of("SYSTEM_RESTART", "SYSTEM_UNLOCK", "SYSTEM_NOTIFY_CHANGE")) {
      add(entries, code, "PLATFORM", "System", false, true, true, "SYSTEM_READ");
    }
    add(entries, "TOKEN_READ", "PLATFORM", "System", true, true, true);
    add(entries, "CONFIG_EXPORT", "PLATFORM", "System", true, true, true);
    add(entries, "CONFIG_IMPORT", "PLATFORM", "System", false, true, true);
    add(entries, "DBSCHEMA_READ", "PLATFORM", "Database", true, true, false);
    for (String action : List.of("CREATE", "UPDATE", "DELETE")) {
      add(
          entries,
          "DBSCHEMA_" + action,
          "PLATFORM",
          "Database",
          false,
          true,
          true,
          "DBSCHEMA_READ");
    }
    add(entries, "CA_READ", "CA", "CA", true, false, false);
    add(entries, "CA_ISSUE_SUBCA", "CA", "CA lifecycle", false, true, true, "CA_READ");
    add(entries, "CA_DETAIL_READ", "CA", "CA", true, true, false, "CA_READ");
    add(entries, "CA_CONFIG_READ", "CA", "CA", true, true, false, "CA_DETAIL_READ");
    for (String code :
        List.of(
            "CA_CONFIG_UPDATE",
            "CA_STATUS_UPDATE",
            "CA_KEY_REPLACE",
            "CA_CERT_REPLACE",
            "CA_CRYPTO_CONFIG_UPDATE",
            "CA_ENGINE_PERMISSIONS_UPDATE")) {
      add(
          entries,
          code,
          "CA",
          "CA configuration",
          false,
          true,
          Set.of("CA_KEY_REPLACE", "CA_CERT_REPLACE", "CA_ENGINE_PERMISSIONS_UPDATE")
              .contains(code),
          "CA_CONFIG_READ");
    }
    for (String code :
        List.of(
            "CA_RESTART",
            "CA_REVOKE",
            "CA_UNREVOKE",
            "CA_DELETE",
            "CA_ALIAS_CREATE",
            "CA_ALIAS_DELETE")) {
      add(
          entries,
          code,
          "CA",
          "CA lifecycle",
          false,
          true,
          Set.of("CA_REVOKE", "CA_UNREVOKE", "CA_DELETE").contains(code),
          "CA_READ");
    }
    for (String kind : List.of("PROFILE", "PUBLISHER", "REQUESTOR")) {
      add(
          entries,
          "CA_" + kind + "_READ",
          "CA",
          kind + " associations",
          true,
          false,
          false,
          "CA_READ");
      for (String action : List.of("BIND", "UNBIND")) {
        add(
            entries,
            "CA_" + kind + "_" + action,
            "CA",
            kind + " associations",
            false,
            true,
            kind.equals("REQUESTOR") && action.equals("BIND"),
            kind.equals("REQUESTOR") && action.equals("BIND")
                ? "CA_REQUESTOR_ACCESS_UPDATE"
                : "CA_" + kind + "_READ");
      }
    }
    add(
        entries,
        "CA_REQUESTOR_ACCESS_READ",
        "CA",
        "REQUESTOR associations",
        true,
        true,
        false,
        "CA_REQUESTOR_READ");
    add(
        entries,
        "CA_REQUESTOR_ACCESS_UPDATE",
        "CA",
        "REQUESTOR associations",
        false,
        true,
        true,
        "CA_REQUESTOR_ACCESS_READ");
    add(entries, "CERT_READ", "CA", "Certificates", true, false, false, "CA_READ");
    add(entries, "CERT_READ_ALL", "CA", "Certificates", true, false, false, "CERT_READ");
    add(entries, "CERT_ISSUE", "CA", "Certificates", false, false, false, "CERT_READ");
    add(entries, "CERT_KEYGEN", "CA", "Certificates", false, true, true, "CERT_READ");
    add(entries, "CERT_CROSS", "CA", "Certificates", false, true, true, "CERT_READ");
    add(entries, "CERT_REVOKE", "CA", "Certificates", false, false, false, "CERT_READ_ALL");
    add(entries, "CERT_SUSPEND", "CA", "Certificates", false, false, false, "CERT_READ_ALL");
    add(entries, "CERT_UNSUSPEND", "CA", "Certificates", false, false, false, "CERT_READ_ALL");
    add(entries, "CERT_DELETE", "CA", "Certificates", false, true, true, "CERT_READ_ALL");
    add(entries, "CERT_REPUBLISH", "CA", "Certificates", false, false, false, "CA_READ");
    add(entries, "CRL_READ", "CA", "CRL", true, false, false, "CA_READ");
    add(entries, "CRL_GENERATE", "CA", "CRL", false, false, false, "CRL_READ");
    ENTRIES = Collections.unmodifiableMap(entries);
  }

  private static void add(
      Map<String, Permission> map,
      String code,
      String scope,
      String group,
      boolean readOnly,
      boolean privileged,
      boolean highRisk,
      String... dependencies) {
    map.put(
        code,
        new Permission(
            code,
            scope,
            group,
            Set.of(dependencies),
            readOnly,
            privileged,
            highRisk,
            ISSUANCE.contains(code),
            false,
            Set.of("ROLE_MANAGE", "USER_ROLE_ASSIGN").contains(code),
            recent(code, scope, readOnly),
            readOnly
                && !Set.of("CONFIG_EXPORT", "TOKEN_READ", "CA_REQUESTOR_ACCESS_READ")
                    .contains(code)));
  }

  private static boolean recent(String code, String scope, boolean readOnly) {
    if (Set.of("CONFIG_EXPORT", "USER_STATUS_UPDATE", "USER_PASSWORD_RESET", "USER_SESSION_REVOKE")
        .contains(code)) {
      return true;
    }
    if (readOnly || Set.of("USER_CREATE", "USER_UPDATE").contains(code)) {
      return false;
    }
    return scope.equals("PLATFORM")
        || Set.of(
                "CA_DELETE",
                "CA_REVOKE",
                "CA_UNREVOKE",
                "CA_KEY_REPLACE",
                "CA_CERT_REPLACE",
                "CA_ENGINE_PERMISSIONS_UPDATE",
                "CA_REQUESTOR_BIND",
                "CA_REQUESTOR_UNBIND",
                "CA_REQUESTOR_ACCESS_UPDATE",
                "CERT_DELETE",
                "CA_ISSUE_SUBCA")
            .contains(code);
  }

  public static Set<String> closure(Collection<String> permissions) {
    var result = new TreeSet<String>();
    for (String code : permissions) {
      expand(code, result, new HashSet<>());
    }
    return Set.copyOf(result);
  }

  private static void expand(String code, Set<String> result, Set<String> path) {
    if (!path.add(code)) {
      throw new IllegalStateException("Permission dependency cycle");
    }
    var p = get(code);
    for (String dependency : p.dependencies()) {
      if (!get(dependency).scope().equals(p.scope())) {
        throw new IllegalStateException("Cross-scope dependency");
      }
      expand(dependency, result, new HashSet<>(path));
    }
    result.add(code);
  }

  public static Collection<Permission> entries() {
    return ENTRIES.values();
  }

  public static Set<String> codes() {
    return ENTRIES.keySet();
  }

  public static Permission get(String code) {
    var value = ENTRIES.get(code);
    if (value == null) {
      throw new RoleValidationException("Unknown permission");
    }
    return value;
  }

  public static void validate(String scope, Set<String> permissions) {
    if (scope == null || !Set.of("CA", "PLATFORM").contains(scope)) {
      throw new RoleValidationException("Invalid role scope");
    }
    for (String code : permissions) {
      var permission = get(code);
      if (permission.reserved()
          || !permission.scope().equals(scope)
          || !permissions.containsAll(permission.dependencies())) {
        throw new RoleValidationException("Invalid permission scope or missing dependencies");
      }
    }
    validateSeparation(permissions, false);
  }

  public static void validateSeparation(Set<String> permissions, boolean superAdmin) {
    if (!superAdmin
        && !Collections.disjoint(permissions, AUDIT)
        && permissions.stream().anyMatch(p -> !get(p).auditCompatible())) {
      throw new RoleValidationException(
          "Audit permissions cannot be combined with write permissions");
    }
  }

  private PermissionCatalog() {}
}
