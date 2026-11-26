// License Apache License 2.0

package org.xipki.mgmt.web.core;

import jakarta.servlet.http.HttpServletRequest;
import org.xipki.mgmt.web.security.WebPrincipal;

/**
 * Request identity is scoped to a single HTTP dispatch, never inherited by worker threads.
 *
 * @author palos
 */
public final class RequestContext {
  private record State(HttpServletRequest request, WebPrincipal principal) {}

  private static final ThreadLocal<State> CURRENT = new ThreadLocal<>();

  public static void bind(HttpServletRequest request, WebPrincipal principal) {
    CURRENT.set(new State(request, principal));
  }

  public static HttpServletRequest request() {
    State state = CURRENT.get();
    return state == null ? null : state.request();
  }

  public static WebPrincipal principal() {
    State state = CURRENT.get();
    return state == null ? null : state.principal();
  }

  public static void clear() {
    CURRENT.remove();
  }

  private RequestContext() {}
}
