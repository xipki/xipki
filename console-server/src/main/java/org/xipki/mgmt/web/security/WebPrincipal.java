// License Apache License 2.0

package org.xipki.mgmt.web.security;

import java.util.*;

/**
 * Immutable database identity. No serialized framework authentication state is accepted.
 *
 * @author palos
 */
public final class WebPrincipal {
  public record Authority(String authority) {
    public String getAuthority() {
      return authority;
    }
  }

  private final long id, authVersion;
  private final String username, password, displayName;
  private final boolean enabled, passwordChangeRequired;
  private final List<RoleBinding> bindings;
  private final Set<Authority> authorities;

  public WebPrincipal(
      long id,
      String username,
      String password,
      boolean enabled,
      String displayName,
      long authVersion,
      boolean passwordChangeRequired,
      List<RoleBinding> bindings) {
    this.id = id;
    this.username = username;
    this.password = password;
    this.enabled = enabled;
    this.displayName = displayName;
    this.authVersion = authVersion;
    this.passwordChangeRequired = passwordChangeRequired;
    this.bindings = List.copyOf(bindings);
    var values = new HashSet<Authority>();
    for (var binding : bindings) {
      if (binding.definition().active()) {
        values.add(new Authority("ROLE_" + binding.role()));
        binding.globalPermissions().forEach(p -> values.add(new Authority("PERM_" + p)));
      }
    }
    this.authorities = Set.copyOf(values);
  }

  public long id() {
    return id;
  }

  public long authVersion() {
    return authVersion;
  }

  public String getUsername() {
    return username;
  }

  public String getPassword() {
    return password;
  }

  public boolean isEnabled() {
    return enabled;
  }

  public String displayName() {
    return displayName;
  }

  public boolean passwordChangeRequired() {
    return passwordChangeRequired;
  }

  public List<RoleBinding> bindings() {
    return bindings;
  }

  public Set<Authority> getAuthorities() {
    return authorities;
  }

  public boolean isSuperAdmin() {
    return bindings.stream()
        .anyMatch(
            b ->
                "SUPER_ADMIN".equals(b.role())
                    && b.definition().active()
                    && "PLATFORM".equals(b.scope()));
  }
}
