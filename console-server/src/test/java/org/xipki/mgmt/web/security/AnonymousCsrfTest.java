// License Apache License 2.0

package org.xipki.mgmt.web.security;

import static org.junit.jupiter.api.Assertions.*;

import jakarta.servlet.http.*;
import java.lang.reflect.Proxy;
import java.util.*;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.xipki.mgmt.web.core.*;

/**
 * @author palos
 */
class AnonymousCsrfTest {
  private final DataSource source =
      (DataSource)
          Proxy.newProxyInstance(
              getClass().getClassLoader(),
              new Class[] {DataSource.class},
              (p, m, a) -> {
                throw new AssertionError(
                    "Anonymous CSRF bootstrap must not access the database: " + m.getName());
              });
  private final Jdbc jdbc = new Jdbc(source);
  private final SessionManager sessions =
      new SessionManager(jdbc, new WebUserDetailsService(jdbc), new Config(Map.of()));

  @Test
  void discardedCookiesDoNotAllocatePersistentSessions() {
    for (int i = 0; i < 100; i++) {
      Browser request = new Browser();
      assertNull(sessions.authenticate(request.request(), request.response()));
      assertNotNull(sessions.csrf(request.request(), request.response()));
      assertEquals(1, request.cookies.size());
    }
  }

  @Test
  void signedCookieAndHeaderAreRequiredAndBootstrapNeverAuthenticates() {
    Browser first = new Browser();
    String csrf = sessions.csrf(first.request(), first.response());
    Browser next = new Browser();
    next.cookie = first.cookie();
    next.header = csrf;
    assertNull(sessions.authenticate(next.request(), next.response()));
    assertDoesNotThrow(() -> sessions.requireCsrf(next.request()));
    next.header = "different";
    assertThrows(AccessDeniedException.class, () -> sessions.requireCsrf(next.request()));
    Browser missing = new Browser();
    missing.header = csrf;
    assertThrows(AccessDeniedException.class, () -> sessions.requireCsrf(missing.request()));
    Browser forged = new Browser();
    forged.cookie = new Cookie(SessionManager.COOKIE, first.cookie().getValue() + "x");
    forged.header = forged.cookie.getValue();
    assertNull(sessions.authenticate(forged.request(), forged.response()));
    assertThrows(AccessDeniedException.class, () -> sessions.requireCsrf(forged.request()));
    SessionManager other =
        new SessionManager(jdbc, new WebUserDetailsService(jdbc), new Config(Map.of()));
    Browser foreign = new Browser();
    foreign.cookie = first.cookie();
    foreign.header = csrf;
    assertNull(other.authenticate(foreign.request(), foreign.response()));
    assertThrows(AccessDeniedException.class, () -> other.requireCsrf(foreign.request()));
  }

  private static final class Browser {
    final Map<String, Object> attributes = new HashMap<>();
    final List<String> cookies = new ArrayList<>();
    Cookie cookie;
    String header;

    Cookie cookie() {
      String[] pair = cookies.get(cookies.size() - 1).split(";", 2)[0].split("=", 2);
      return new Cookie(pair[0], pair[1]);
    }

    HttpServletRequest request() {
      return (HttpServletRequest)
          Proxy.newProxyInstance(
              getClass().getClassLoader(),
              new Class[] {HttpServletRequest.class},
              (p, m, a) ->
                  switch (m.getName()) {
                    case "getCookies" -> cookie == null ? null : new Cookie[] {cookie};
                    case "getHeader" -> "X-CSRF-TOKEN".equals(a[0]) ? header : null;
                    case "getAttribute" -> attributes.get(a[0]);
                    case "setAttribute" -> attributes.put((String) a[0], a[1]);
                    case "removeAttribute" -> attributes.remove(a[0]);
                    default -> null;
                  });
    }

    HttpServletResponse response() {
      return (HttpServletResponse)
          Proxy.newProxyInstance(
              getClass().getClassLoader(),
              new Class[] {HttpServletResponse.class},
              (p, m, a) -> {
                if (m.getName().equals("addHeader") && a[0].equals("Set-Cookie")) {
                  cookies.add((String) a[1]);
                }
                return null;
              });
    }
  }
}
