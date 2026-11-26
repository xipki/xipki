// License Apache License 2.0

package org.xipki.mgmt.web.dto;

import java.util.List;
import org.xipki.mgmt.web.core.*;

/**
 * @author palos
 */
public final class RoleRequests {
  public static class Fields extends StrictRequest {
    public String displayName;
    public String description;
    public List<String> permissions;
    public Boolean confirmed;
  }

  public static class Create extends Fields {
    public String name;
    public String scope;
  }

  public static class Update extends Fields {
    public Long revision;
    public Boolean enabled;
  }

  private RoleRequests() {}
}
