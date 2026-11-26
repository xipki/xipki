// License Apache License 2.0

package org.xipki.mgmt.web.security;

import java.io.Serializable;
import java.util.*;
import org.xipki.mgmt.web.core.*;

/**
 * @author palos
 */
public record RoleBinding(
    String role,
    String scope,
    String caName,
    String caFingerprint,
    boolean allProfiles,
    List<String> profiles,
    RoleDefinition definition)
    implements Serializable {
  public RoleBinding {
    if (definition == null || !definition.name().equals(role) || definition.deleted()) {
      throw new IllegalArgumentException("Invalid role");
    }
    if (scope == null
        || !Set.of("PLATFORM", "NAMED_CA", "ALL_CAS").contains(scope)
        || "PLATFORM".equals(definition.scope()) != "PLATFORM".equals(scope)) {
      throw new IllegalArgumentException("Invalid role scope");
    }
    if ("NAMED_CA".equals(scope)) {
      if (caName == null || caName.isBlank() || caFingerprint == null || caFingerprint.isBlank()) {
        throw new IllegalArgumentException("Named CA requires identity");
      }
    } else if (caName != null || caFingerprint != null) {
      throw new IllegalArgumentException("Unexpected CA identity");
    }
    profiles = profiles == null ? List.of() : List.copyOf(profiles);
    if (profiles.size() > 200
        || profiles.stream().anyMatch(p -> p == null || !p.matches("[a-zA-Z0-9_.-]{1,128}"))) {
      throw new IllegalArgumentException("Invalid profiles");
    }
    if ("PLATFORM".equals(scope) && (allProfiles || !profiles.isEmpty())
        || allProfiles && !profiles.isEmpty()) {
      throw new IllegalArgumentException("Invalid profile scope");
    }
  }

  public boolean allows(String permission, String ca, String fingerprint, String profile) {
    if (!definition.active() || !definition.permissions().contains(permission)) {
      return false;
    }
    if ("SUPER_ADMIN".equals(role)) {
      return true;
    }
    if ("PLATFORM".equals(scope)) {
      return false;
    }
    if ("NAMED_CA".equals(scope)
        && (!Objects.equals(caName, ca) || !Objects.equals(caFingerprint, fingerprint))) {
      return false;
    }
    if (!PermissionCatalog.get(permission).scope().equals("CA")) {
      return false;
    }
    return !PermissionCatalog.ISSUANCE.contains(permission)
        || (profile != null && (allProfiles || profiles.contains(profile)));
  }

  /** Coarse UI/method authorities. These never replace allows() on an individual CA. */
  public Set<String> globalPermissions() {
    if (!definition.active()) {
      return Set.of();
    }
    var permissions = new TreeSet<>(definition.permissions());
    if (!"SUPER_ADMIN".equals(role)) {
      permissions.removeIf(p -> !PermissionCatalog.get(p).scope().equals(definition.scope()));
    }
    return Collections.unmodifiableSet(permissions);
  }
}
