// License Apache License 2.0

package org.xipki.mgmt.web.security;

import static org.junit.jupiter.api.Assertions.*;

import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * @author palos
 */
class IdentitySecurityTest {
  @Test
  void forcedPasswordChangeRestrictsEvenSuperAdministratorsToRecoveryRoutes() {
    var role =
        new RoleDefinition(
            "SUPER_ADMIN",
            "Super",
            "",
            "PLATFORM",
            true,
            true,
            false,
            1,
            PermissionCatalog.codes());
    var principal =
        new WebPrincipal(
            1,
            "admin",
            "hash",
            true,
            null,
            1,
            true,
            List.of(
                new RoleBinding("SUPER_ADMIN", "PLATFORM", null, null, false, List.of(), role)));
    for (var rule : ManagementApiPolicy.rules()) {
      var request =
          (HttpServletRequest)
              Proxy.newProxyInstance(
                  getClass().getClassLoader(),
                  new Class<?>[] {HttpServletRequest.class},
                  (p, m, args) ->
                      switch (m.getName()) {
                        case "getMethod" -> rule.method();
                        case "getRequestURI" -> rule.path();
                        default -> null;
                      });
      boolean expected =
          rule.path().startsWith("/health/")
              || Set.of("/api/auth/me", "/api/auth/csrf", "/api/auth/password", "/api/auth/logout")
                  .contains(rule.path());
      assertEquals(
          expected,
          ManagementApiPolicy.authorized(request, principal),
          rule.method() + " " + rule.path());
    }
  }

  @Test
  void scopedAuthorityNeverGrantsAnotherCaOrProfile() {
    var role =
        new RoleDefinition(
            "ISSUER", "Issuer", "", "CA", false, true, false, 1, Set.of("CA_READ", "CERT_ISSUE"));
    var binding = new RoleBinding("ISSUER", "NAMED_CA", "ca1", "abc", false, List.of("tls"), role);
    assertTrue(binding.allows("CERT_ISSUE", "ca1", "abc", "tls"));
    assertFalse(binding.allows("CERT_ISSUE", "ca1", "other", "tls"));
    assertFalse(binding.allows("CERT_ISSUE", "ca2", "abc", "tls"));
    assertFalse(binding.allows("CERT_ISSUE", "ca1", "abc", "other"));
  }

  @Test
  void disabledRoleDoesNotContributeAuthorities() {
    var role =
        new RoleDefinition("READER", "Reader", "", "CA", false, false, false, 1, Set.of("CA_READ"));
    var principal =
        new WebPrincipal(
            1,
            "alice",
            "hash",
            true,
            null,
            1,
            false,
            List.of(new RoleBinding("READER", "ALL_CAS", null, null, false, List.of(), role)));
    assertTrue(principal.getAuthorities().isEmpty());
    assertFalse(principal.isSuperAdmin());
  }

  @Test
  void mostSpecificPolicyWinsAndUnknownPathsFailClosed() {
    assertEquals("/api/ca/aliases", ManagementApiPolicy.match("GET", "/api/ca/aliases").path());
    assertNull(ManagementApiPolicy.match("POST", "/api/unknown"));
    assertNull(ManagementApiPolicy.match("GET", "/api/ca/a/extra"));
  }

  @Test
  void recentAuthenticationAndIdleExpiryRejectFutureAndStaleTimes() {
    assertTrue(SessionManager.recent(1000L, 1001L));
    assertFalse(SessionManager.recent(1002L, 1001L));
    assertFalse(SessionManager.recent(1L, 300002L));
    assertTrue(SessionManager.expired(1000, 1801000));
    assertFalse(SessionManager.expired(1000, 1800999));
  }

  @Test
  void storedSessionHashesAreNotBearerTokens() {
    String token = SessionManager.token();
    assertEquals(43, token.length());
    assertEquals(64, SessionManager.hash(token).length());
    assertNotEquals(token, SessionManager.hash(token));
    assertNotEquals(token, SessionManager.token());
  }
}
