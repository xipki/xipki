// License Apache License 2.0

package org.xipki.mgmt.web.security;

import static org.junit.jupiter.api.Assertions.*;

import jakarta.servlet.http.*;
import java.lang.reflect.Proxy;
import java.util.*;
import org.junit.jupiter.api.*;
import org.xipki.mgmt.web.audit.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.db.*;
import org.xipki.mgmt.web.security.AccessControl.CaIdentity;

/**
 * Opt-in, non-destructive verification against an explicitly dedicated disposable database.
 *
 * @author palos
 */
class IdentityDatabaseTest {
  private static final String ADMIN = "lite-bootstrap", PASSWORD = "lite bootstrap test password";
  private static DatabaseSource source;
  private static Jdbc jdbc;
  private static Transactions tx;
  private static Password passwords;
  private static WebUserDetailsService users;
  private static AuditService audit;
  private static SessionManager sessions;

  @BeforeAll
  static void database() {
    String url = System.getenv("WEB_LITE_TEST_DB_URL");
    if (Boolean.getBoolean("lite.db.required")) {
      assertNotNull(url, "WEB_LITE_TEST_DB_URL is required when -Dlite.db.required=true");
    }
    Assumptions.assumeTrue(
        url != null, "Set WEB_LITE_TEST_DB_URL for disposable database integration tests");
    assertTrue(
        url.matches(
            "jdbc:(?:mariadb|postgresql)://(?:127\\.0\\.0\\.1|localhost):[0-9]+/"
                + "xipki_web_lite_tests"),
        "Only the dedicated local xipki_web_lite_tests database is accepted");
    String secret = System.getenv("WEB_LITE_TEST_DB_PASSWORD");
    assertNotNull(secret, "WEB_LITE_TEST_DB_PASSWORD is required");
    source =
        new DatabaseSource(
            url, System.getenv().getOrDefault("WEB_LITE_TEST_DB_USER", "root"), secret);
    jdbc = new Jdbc(source);
    tx = new Transactions(jdbc);
    passwords = new Password();
    users = new WebUserDetailsService(jdbc);
    audit = new AuditService(jdbc);
    new WebSchemaInitializer(source, ADMIN, PASSWORD).ensureCurrent();
    sessions = new SessionManager(jdbc, users, new Config(Map.of()), audit);
  }

  @AfterEach
  void clear() {
    RequestContext.clear();
  }

  @Test
  void schemaVersionAndExistingAccountsSurviveRepeatedStartup() {
    long count = jdbc.queryForObject("SELECT COUNT(*) FROM web_user", Long.class);
    String hash = users.loadUserByUsername(ADMIN).getPassword();
    new WebSchemaInitializer(source, "ignored-bootstrap", "another bootstrap password")
        .ensureCurrent();
    assertEquals(6, jdbc.queryForObject("SELECT version FROM web_schema_version", Integer.class));
    assertEquals(count, jdbc.queryForObject("SELECT COUNT(*) FROM web_user", Long.class));
    assertEquals(hash, users.loadUserByUsername(ADMIN).getPassword());
    assertTrue(passwords.matches(PASSWORD, hash));
    assertTrue(new WebDatabaseHealth(jdbc).isReady());
  }

  @Test
  void certificateOwnershipCursorVisitsEveryOwnedSerial() {
    administrator();
    var identity = new CaIdentity("ownership-test", "f".repeat(64));
    long userId = AccountService.principal().id();
    try {
      for (int serial = 1; serial <= 101; serial++) {
        jdbc.update(
            "INSERT INTO"
                + " web_certificate_owner(ca_name,ca_fingerprint,serial_number,user_id,"
                + "profile_name)"
                + " VALUES (?,?,?,?,?)",
            identity.name(),
            identity.fingerprint(),
            Integer.toHexString(serial),
            userId,
            "test");
      }
      var ownership = new CertificateOwnership(jdbc);
      assertEquals(101, ownership.serials(identity, 1001).size());
      var seen = new HashSet<String>();
      String cursor = null;
      int pages = 0;
      do {
        var page = ownership.page(identity, cursor);
        assertTrue(page.serials().size() <= 5);
        for (String serial : page.serials()) {
          assertTrue(seen.add(serial), "Cursor pages must not repeat serials");
        }
        cursor = page.nextCursor();
        pages++;
      } while (cursor != null);
      assertEquals(21, pages);
      assertEquals(101, seen.size());
      assertThrows(
          IllegalArgumentException.class, () -> ownership.page(identity, "invalid-cursor"));
    } finally {
      jdbc.update(
          "DELETE FROM web_certificate_owner WHERE ca_name=? AND ca_fingerprint=? AND user_id=?",
          identity.name(),
          identity.fingerprint(),
          userId);
    }
  }

  @Test
  void fixationCsrfIdleRecentAndVersionRevocationUseStoredState() {
    Exchange initial = new Exchange();
    String oldCsrf = sessions.csrf(initial.req, initial.resp), oldCookie = initial.cookie();
    var admin = users.loadUserByUsername(ADMIN);
    sessions.login(initial.req, initial.resp, admin);
    String cookie = initial.cookie();
    assertNotEquals(oldCookie, cookie);
    String csrf = sessions.csrf(initial.req, initial.resp);
    assertNotEquals(oldCsrf, csrf);
    assertTrue(
        SessionManager.recent(
            SessionManager.reauthenticatedAt(initial.req), System.currentTimeMillis()));
    Exchange authenticated = new Exchange(cookie);
    assertNotNull(sessions.authenticate(authenticated.req, authenticated.resp));
    assertThrows(AccessDeniedException.class, () -> sessions.requireCsrf(authenticated.req));
    authenticated.headers.put("X-CSRF-TOKEN", oldCsrf);
    assertThrows(AccessDeniedException.class, () -> sessions.requireCsrf(authenticated.req));
    authenticated.headers.put("X-CSRF-TOKEN", csrf);
    assertDoesNotThrow(() -> sessions.requireCsrf(authenticated.req));
    String digest = SessionManager.hash(cookie);
    jdbc.update("UPDATE lite_session SET recent_auth_ms=0 WHERE token_hash=?", digest);
    Exchange stale = new Exchange(cookie);
    sessions.authenticate(stale.req, stale.resp);
    RequestContext.bind(stale.req, admin);
    assertThrows(AccessDeniedException.class, RecentAuthentication::require);
    sessions.confirm(stale.req);
    assertDoesNotThrow(RecentAuthentication::require);
    jdbc.update(
        "UPDATE lite_session SET last_access_ms=? WHERE token_hash=?",
        System.currentTimeMillis() - 1_800_001,
        digest);
    assertNull(sessions.authenticate(new Exchange(cookie).req, new Exchange().resp));
    assertThrows(AccessDeniedException.class, () -> sessions.confirm(stale.req));
    assertNull(sessions.authenticate(new Exchange(oldCookie).req, new Exchange().resp));
  }

  @Test
  void accountVersionsAndDisabledUsersInvalidateSessionsAndStaleLogin() {
    var created = createUser();
    long id = ((Number) created.get("id")).longValue();
    String name = (String) created.get("username");
    var user = users.loadUserByUsername(name);
    Exchange login = new Exchange();
    sessions.login(login.req, login.resp, user);
    String cookie = login.cookie();
    jdbc.update("UPDATE web_user SET auth_version=auth_version+1 WHERE id=?", id);
    assertNull(sessions.authenticate(new Exchange(cookie).req, new Exchange().resp));
    assertEquals(
        401,
        assertThrows(
                ApiException.class,
                () -> sessions.login(new Exchange().req, new Exchange().resp, user))
            .status());
    var freshUser = users.loadUserByUsername(name);
    Exchange enabled = new Exchange();
    sessions.login(enabled.req, enabled.resp, freshUser);
    String enabledCookie = enabled.cookie();
    jdbc.update("UPDATE web_user SET enabled=FALSE WHERE id=?", id);
    assertNull(sessions.authenticate(new Exchange(enabledCookie).req, new Exchange().resp));
    WebPrincipal stale = users.loadUserByUsername(name);
    assertEquals(
        401,
        assertThrows(
                ApiException.class,
                () -> sessions.login(new Exchange().req, new Exchange().resp, stale))
            .status());
  }

  @Test
  void identityAndRoleMutationsRollbackWhenAuditFails() {
    administrator();
    String username = "rollback-" + UUID.randomUUID().toString().substring(0, 8);
    AuditService unavailable =
        new AuditService(jdbc) {
          @Override
          public void authorizationChange(
              String a, String t, String id, Object before, Object after) {
            throw new IllegalStateException("test audit unavailable");
          }
        };
    assertThrows(
        IllegalStateException.class, () -> accounts(unavailable).create(username, "Rollback"));
    assertEquals(
        0,
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM web_user WHERE username=?", Integer.class, username));
    String role = "TEST_" + UUID.randomUUID().toString().substring(0, 8).toUpperCase(Locale.ROOT);
    assertThrows(
        IllegalStateException.class,
        () ->
            new RoleService(jdbc, tx, unavailable)
                .save(role, null, "Rollback", "", "CA", true, List.of("CA_READ"), true));
    assertEquals(
        0, jdbc.queryForObject("SELECT COUNT(*) FROM web_role WHERE name=?", Integer.class, role));
  }

  @Test
  void committedRoleEditRevokesExistingSessionAndRejectsLostUpdate() {
    var created = createUser();
    long id = ((Number) created.get("id")).longValue();
    String username = (String) created.get("username");
    administrator();
    String name = "TEST_" + UUID.randomUUID().toString().substring(0, 8).toUpperCase(Locale.ROOT);
    var roleService = new RoleService(jdbc, tx, audit);
    var role = roleService.save(name, null, "Reader", "", "CA", true, List.of("CA_READ"), true);
    accounts(audit)
        .replaceBindings(
            id,
            List.of(accounts(audit).resolveBinding(name, "ALL_CAS", null, null, false, List.of())));
    var user = users.loadUserByUsername(username);
    assertTrue(
        user.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("PERM_CA_READ")));
    Exchange exchange = new Exchange();
    sessions.login(exchange.req, exchange.resp, user);
    String cookie = exchange.cookie();
    administrator();
    var disabled =
        roleService.save(
            name, role.revision(), "Reader", "", "CA", false, List.of("CA_READ"), true);
    assertTrue(disabled.revision() > role.revision());
    assertTrue(users.loadUserByUsername(username).authVersion() > user.authVersion());
    assertTrue(users.loadUserByUsername(username).getAuthorities().isEmpty());
    assertNull(sessions.authenticate(new Exchange(cookie).req, new Exchange().resp));
    assertEquals(
        409,
        assertThrows(
                ApiException.class,
                () ->
                    roleService.save(
                        name,
                        role.revision(),
                        "Old edit",
                        "",
                        "CA",
                        true,
                        List.of("CA_READ"),
                        true))
            .status());
  }

  @Test
  void lastAdministratorProtectionAndRoleSeparationRollback() {
    administrator();
    long id = users.loadUserByUsername(ADMIN).id();
    assertEquals(
        1,
        jdbc.queryForObject(
            "SELECT COUNT(DISTINCT u.id) FROM web_user u JOIN web_role_binding b ON u.id=b.user_id"
                + " WHERE b.role_name='SUPER_ADMIN' AND u.enabled=TRUE",
            Integer.class),
        "Fixture must have exactly one bootstrap super administrator");
    assertThrows(IllegalArgumentException.class, () -> accounts(audit).setEnabled(id, false));
    assertTrue(users.loadUserByUsername(ADMIN).isEnabled());
    assertThrows(
        IllegalArgumentException.class, () -> accounts(audit).replaceBindings(id, List.of()));
    assertTrue(users.loadUserByUsername(ADMIN).isSuperAdmin());
    var created = createUser();
    administrator();
    long other = ((Number) created.get("id")).longValue();
    assertThrows(
        IllegalArgumentException.class,
        () ->
            accounts(audit)
                .replaceBindings(
                    other,
                    List.of(
                        accounts(audit)
                            .resolveBinding("AUDITOR", "PLATFORM", null, null, false, List.of()),
                        accounts(audit)
                            .resolveBinding(
                                "CERT_OPERATOR", "ALL_CAS", null, null, false, List.of()))));
    assertTrue(users.bindings(other).isEmpty());
  }

  @Test
  void cleanupIsBoundedAndAuditFailureRollsBackRemoval() {
    administrator();
    Exchange login = new Exchange();
    sessions.login(login.req, login.resp, users.loadUserByUsername(ADMIN));
    String digest = SessionManager.hash(login.cookie());
    jdbc.update(
        "UPDATE lite_session SET last_access_ms=? WHERE token_hash=?",
        System.currentTimeMillis() - 1_800_001,
        digest);
    AuditService unavailable =
        new AuditService(jdbc) {
          @Override
          public void record(AuditEvent event) {
            throw new IllegalStateException("test audit unavailable");
          }
        };
    assertThrows(
        IllegalStateException.class,
        () -> new SessionManager(jdbc, users, new Config(Map.of()), unavailable).cleanup());
    assertEquals(
        1,
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM lite_session WHERE token_hash=?", Integer.class, digest));
    sessions.cleanup();
    assertEquals(
        0,
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM lite_session WHERE token_hash=?", Integer.class, digest));
    assertTrue(
        jdbc.queryForObject(
                "SELECT COUNT(*) FROM web_audit_event WHERE action='SESSION_EXPIRED' AND"
                    + " resource_id=?",
                Integer.class,
                digest)
            > 0);
  }

  private static Map<String, Object> createUser() {
    administrator();
    return accounts(audit)
        .create("user-" + UUID.randomUUID().toString().substring(0, 8), "Test user");
  }

  private static AccountService accounts(AuditService service) {
    return new AccountService(jdbc, passwords, users, service, tx);
  }

  private static void administrator() {
    Exchange exchange = new Exchange();
    sessions.login(exchange.req, exchange.resp, users.loadUserByUsername(ADMIN));
    RequestContext.bind(exchange.req, users.loadUserByUsername(ADMIN));
  }

  /** Servlet-only fixtures exercise the real database/session logic without Spring mocks. */
  private static final class Exchange {
    final Map<String, Object> attributes = new HashMap<>();
    final Map<String, String> headers = new HashMap<>();
    final List<String> cookies = new ArrayList<>();
    final HttpServletRequest req;
    final HttpServletResponse resp;

    Exchange() {
      this(null);
    }

    Exchange(String bearer) {
      req =
          (HttpServletRequest)
              Proxy.newProxyInstance(
                  getClass().getClassLoader(),
                  new Class<?>[] {HttpServletRequest.class},
                  (p, m, a) ->
                      switch (m.getName()) {
                        case "getAttribute" -> attributes.get(a[0]);
                        case "setAttribute" -> {
                          attributes.put((String) a[0], a[1]);
                          yield null;
                        }
                        case "removeAttribute" -> {
                          attributes.remove(a[0]);
                          yield null;
                        }
                        case "getCookies" ->
                            bearer == null
                                ? null
                                : new Cookie[] {new Cookie(SessionManager.COOKIE, bearer)};
                        case "getHeader" -> headers.get(a[0]);
                        case "getRemoteAddr" -> "127.0.0.1";
                        case "getMethod" -> "POST";
                        case "getRequestURI" -> "/api/auth/reauth";
                        default -> primitive(m.getReturnType());
                      });
      resp =
          (HttpServletResponse)
              Proxy.newProxyInstance(
                  getClass().getClassLoader(),
                  new Class<?>[] {HttpServletResponse.class},
                  (p, m, a) -> {
                    if (m.getName().equals("addHeader") && a[0].equals("Set-Cookie")) {
                      cookies.add((String) a[1]);
                    }
                    return primitive(m.getReturnType());
                  });
    }

    String cookie() {
      return cookies.get(cookies.size() - 1).split(";", 2)[0].split("=", 2)[1];
    }

    private static Object primitive(Class<?> type) {
      if (type == boolean.class) {
        return false;
      }
      if (type == int.class) {
        return 0;
      }
      if (type == long.class) {
        return 0L;
      }
      return null;
    }
  }
}
