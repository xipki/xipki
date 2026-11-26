// License Apache License 2.0

package org.xipki.mgmt.web.dto;

import java.util.List;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.core.*;

/**
 * @author palos
 */
public class ProfileAssociationRequest extends StrictRequest {
  public List<String> aliases = List.of();

  public List<String> getAliases() {
    return aliases;
  }

  public void setAliases(List<String> aliases) {
    this.aliases = aliases;
  }

  public String encoded(String name) {
    validName(name);
    if (aliases == null) {
      throw new IllegalArgumentException("aliases must be a list");
    }
    aliases.forEach(ProfileAssociationRequest::validName);
    return new CaProfileEntry(name, aliases).getEncoded();
  }

  private static void validName(String value) {
    if (value == null || !value.matches("[A-Za-z0-9_.-]+")) {
      throw new IllegalArgumentException("Invalid profile name or alias");
    }
  }
}
