// License Apache License 2.0

package org.xipki.mgmt.web.security;

import java.util.*;
import org.xipki.mgmt.web.core.*;

/**
 * Installation/migration defaults only. Runtime editable grants are read by RoleCatalog.
 *
 * @author palos
 */
public final class BuiltinRoles {
  public static final Set<String> PLATFORM_ROLES = Set.of("SUPER_ADMIN", "USER_ADMIN", "AUDITOR");
  private static final Map<String, Set<String>> ROLES;

  static {
    var roles = new LinkedHashMap<String, Set<String>>();
    roles.put("USER_ADMIN", Set.of("USER_MANAGE", "ROLE_READ"));
    roles.put(
        "CA_ADMIN",
        Set.of(
            "CA_READ", "CA_CONFIG", "CA_CONFIG_READ", "CA_CREATE", "SHARED_READ", "SHARED_CONFIG"));
    roles.put("CERT_REQUESTER", Set.of("CA_READ", "CERT_READ", "CERT_ISSUE"));
    roles.put(
        "CERT_OPERATOR",
        Set.of(
            "CA_READ",
            "CERT_READ",
            "CERT_READ_ALL",
            "CERT_REVOKE",
            "CRL_MANAGE",
            "CERT_REPUBLISH"));
    roles.put("AUDITOR", Set.of("AUDIT_READ", "AUDIT_EXPORT", "AUDIT_CONTEXT_READ", "ROLE_READ"));
    roles.put("VIEWER", Set.of("CA_READ"));
    var all = new TreeSet<String>();
    roles.values().forEach(all::addAll);
    all.addAll(
        Set.of(
            "ROLE_MANAGE",
            "CA_DELETE",
            "CERT_DELETE",
            "CERT_KEYGEN",
            "CERT_CROSS",
            "SYSTEM_ADMIN",
            "CONFIG_EXPORT",
            "CONFIG_IMPORT"));
    var ordered = new LinkedHashMap<String, Set<String>>();
    ordered.put("SUPER_ADMIN", Collections.unmodifiableSet(all));
    ordered.putAll(roles);
    ROLES = Collections.unmodifiableMap(ordered);
  }

  public static Set<String> permissions(String role) {
    Set<String> permissions = ROLES.get(role);
    if (permissions == null) {
      throw new IllegalArgumentException("Unknown role");
    }
    return permissions;
  }

  public static Map<String, Set<String>> roles() {
    return ROLES;
  }

  private BuiltinRoles() {}
}
