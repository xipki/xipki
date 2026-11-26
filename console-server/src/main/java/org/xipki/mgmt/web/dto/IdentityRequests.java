// License Apache License 2.0

package org.xipki.mgmt.web.dto;

import java.util.List;
import org.xipki.mgmt.web.core.*;

/**
 * @author palos
 */
public final class IdentityRequests {
  public static class Create extends StrictRequest {
    public String username;
    public String displayName;
  }

  public static class Update extends StrictRequest {
    public String displayName;
  }

  public static class Status extends StrictRequest {
    public Boolean enabled;
  }

  public static class Binding extends StrictRequest {
    public String role;
    public String scope;
    public String caName;
    public String caFingerprint;
    public Boolean allProfiles;
    public List<String> profiles;
  }

  public static class Bindings extends StrictRequest {
    public List<Binding> bindings;
  }

  public static class Password extends StrictRequest {
    public String currentPassword;
    public String newPassword;
  }

  public static class Reauth extends StrictRequest {
    public String password;
  }

  private IdentityRequests() {}
}
