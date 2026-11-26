// License Apache License 2.0

package org.xipki.mgmt.web.security;

import jakarta.servlet.http.HttpServletRequest;
import org.xipki.mgmt.web.core.*;

/**
 * @author palos
 */
public final class RecentAuthentication {
  public static final String ATTRIBUTE = "web.reauthenticatedAt";

  public static void require() {
    var request = RequestContext.request();
    if (request == null
        || !SessionManager.recent(
            SessionManager.reauthenticatedAt(request), System.currentTimeMillis())) {
      throw new AccessDeniedException("Reauthentication required");
    }
  }

  public static void confirm(HttpServletRequest request) {
    SessionManager.confirm(request);
  }

  private RecentAuthentication() {}
}
