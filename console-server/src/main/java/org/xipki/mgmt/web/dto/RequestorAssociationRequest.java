// License Apache License 2.0

package org.xipki.mgmt.web.dto;

import java.util.List;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.core.*;

/**
 * @author palos
 */
public class RequestorAssociationRequest extends StrictRequest {
  public List<String> permissions = List.of("all");
  public List<String> profiles = List.of("all");
  public boolean confirmNonAtomic;

  public List<String> getPermissions() {
    return permissions;
  }

  public void setPermissions(List<String> permissions) {
    this.permissions = permissions;
  }

  public List<String> getProfiles() {
    return profiles;
  }

  public void setProfiles(List<String> profiles) {
    this.profiles = profiles;
  }

  public boolean isConfirmNonAtomic() {
    return confirmNonAtomic;
  }

  public void setConfirmNonAtomic(boolean confirmNonAtomic) {
    this.confirmNonAtomic = confirmNonAtomic;
  }

  public CaHasRequestorEntry entry(String name) {
    if (permissions == null
        || permissions.isEmpty()
        || permissions.stream().anyMatch(p -> p == null || p.isBlank())
        || profiles == null
        || profiles.stream().anyMatch(p -> p == null || p.isBlank())) {
      throw new IllegalArgumentException("Invalid permissions or profile restrictions");
    }
    try {
      Permissions parsed = new Permissions(permissions);
      int allowed = new Permissions(List.of("all")).getValue();
      if ((parsed.getValue() & ~allowed) != 0) {
        throw new IllegalArgumentException("Unsupported permission bits");
      }
      return new CaHasRequestorEntry(new NameId(null, name), parsed, profiles);
    } catch (IllegalArgumentException ex) {
      throw new IllegalArgumentException("Invalid permissions");
    }
  }
}
