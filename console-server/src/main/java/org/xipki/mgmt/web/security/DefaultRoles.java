// License Apache License 2.0

package org.xipki.mgmt.web.security;

import java.util.*;
import org.xipki.mgmt.web.core.*;

/**
 * v4 installation templates only. Runtime grants are always loaded from MariaDB.
 *
 * @author palos
 */
public final class DefaultRoles {
  public static final Set<String> PLATFORM_ROLES =
      Set.of("SUPER_ADMIN", "USER_ADMIN", "AUDITOR", "SHARED_RESOURCE_ADMIN");
  private static final Map<String, Set<String>> ROLES;

  static {
    var roles = new LinkedHashMap<String, Set<String>>();
    roles.put("SUPER_ADMIN", PermissionCatalog.codes());
    roles.put(
        "USER_ADMIN",
        PermissionCatalog.closure(
            Set.of(
                "USER_CREATE",
                "USER_UPDATE",
                "USER_STATUS_UPDATE",
                "USER_PASSWORD_RESET",
                "USER_SESSION_REVOKE",
                "ROLE_READ")));
    var ca = new TreeSet<String>();
    PermissionCatalog.entries().stream()
        .filter(
            p ->
                p.scope().equals("CA")
                    && p.code().startsWith("CA_")
                    && !Set.of("CA_DELETE", "CA_ISSUE_SUBCA").contains(p.code()))
        .forEach(p -> ca.add(p.code()));
    roles.put("CA_ADMIN", PermissionCatalog.closure(ca));
    roles.put("CERT_REQUESTER", PermissionCatalog.closure(Set.of("CERT_ISSUE")));
    roles.put(
        "CERT_OPERATOR",
        PermissionCatalog.closure(
            Set.of(
                "CERT_REVOKE",
                "CERT_SUSPEND",
                "CERT_UNSUSPEND",
                "CRL_GENERATE",
                "CERT_REPUBLISH")));
    roles.put("AUDITOR", PermissionCatalog.closure(Set.of("AUDIT_EXPORT", "AUDIT_CONTEXT_READ")));
    roles.put("VIEWER", Set.of("CA_READ", "CRL_READ"));
    var shared = new TreeSet<String>();
    PermissionCatalog.entries().stream()
        .filter(
            p ->
                Set.of("SIGNER", "REQUESTOR", "PUBLISHER", "PROFILE", "KEYPAIRGEN")
                    .contains(p.group()))
        .forEach(p -> shared.add(p.code()));
    roles.put("SHARED_RESOURCE_ADMIN", PermissionCatalog.closure(shared));
    ROLES = Collections.unmodifiableMap(roles);
  }

  public static Map<String, Set<String>> roles() {
    return ROLES;
  }

  private DefaultRoles() {}
}
