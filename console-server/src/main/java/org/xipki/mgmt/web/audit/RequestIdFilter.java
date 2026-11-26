// License Apache License 2.0

package org.xipki.mgmt.web.audit;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.UUID;

/**
 * @author palos
 */
public final class RequestIdFilter {
  public static final String ATTRIBUTE = RequestIdFilter.class.getName() + ".requestId";

  public static void apply(HttpServletRequest request, HttpServletResponse response) {
    String id = request.getHeader("X-Request-ID");
    if (id == null || !id.matches("[A-Za-z0-9._:-]{1,128}")) {
      id = UUID.randomUUID().toString();
    }
    request.setAttribute(ATTRIBUTE, id);
    response.setHeader("X-Request-ID", id);
  }

  private RequestIdFilter() {}
}
