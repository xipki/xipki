// License Apache License 2.0

package org.xipki.mgmt.web.security;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;
import org.junit.jupiter.api.*;
import org.xipki.mgmt.web.audit.AuditService;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.db.WebSchemaInitializer;

/**
 * Uses only an explicitly supplied disposable local database; never resets existing users.
 *
 * @author palos
 */
class PasswordUpgradeDatabaseTest {
  private static Jdbc jdbc;
  private static WebUserDetailsService users;
  private static AccountService accounts;
  private static final String LEGACY =
      "$2a$10$......................7zqaLmaKtn.i7IjPfuPGY2Ah/mNM6Sy";

  @BeforeAll
  static void database() {
    String url = System.getenv("WEB_LITE_TEST_DB_URL");
    if (Boolean.getBoolean("lite.db.required")) {
      assertNotNull(url);
    }
    Assumptions.assumeTrue(url != null, "Disposable MariaDB or PostgreSQL required");
    assertTrue(
        url.matches(
            "jdbc:(?:mariadb|postgresql)://(?:127\\.0\\.0\\.1|localhost):[0-9]+/"
                + "xipki_web_lite_tests"));
    var source =
        new DatabaseSource(
            url,
            System.getenv().getOrDefault("WEB_LITE_TEST_DB_USER", "root"),
            Objects.requireNonNull(System.getenv("WEB_LITE_TEST_DB_PASSWORD")));
    new WebSchemaInitializer(source, "lite-bootstrap", "lite bootstrap test password")
        .ensureCurrent();
    jdbc = new Jdbc(source);
    users = new WebUserDetailsService(jdbc);
    accounts =
        new AccountService(
            jdbc, new Password(), users, new AuditService(jdbc), new Transactions(jdbc));
  }

  private WebPrincipal legacy() {
    String name = "legacy-" + UUID.randomUUID();
    jdbc.update(
        "INSERT INTO web_user(username,password_hash,password_change_required) VALUES (?,?,FALSE)",
        name,
        LEGACY);
    return users.loadUserByUsername(name);
  }

  @AfterEach
  void clear() {
    RequestContext.clear();
  }

  @Test
  void upgradePreservesIdentityAndSessionsAndRejectsUnverifiedPassword() {
    var user = legacy();
    try {
      assertThrows(ApiException.class, () -> accounts.upgradePasswordAfterLogin(user, "incorrect"));
      assertEquals(LEGACY, users.loadUserByUsername(user.getUsername()).getPassword());
      var fresh = accounts.upgradePasswordAfterLogin(user, "password");
      assertEquals(user.id(), fresh.id());
      assertEquals(user.authVersion(), fresh.authVersion());
      assertFalse(fresh.passwordChangeRequired());
      assertTrue(fresh.getPassword().startsWith("$pbkdf2-sha256$"));
      assertTrue(new Password().matches("password", fresh.getPassword()));
      assertEquals(
          fresh.getPassword(), accounts.upgradePasswordAfterLogin(user, "password").getPassword());
    } finally {
      jdbc.update("DELETE FROM web_user WHERE id=?", user.id());
    }
  }

  @Test
  void staleAuthenticationCannotOverwriteChangedPasswordOrDisabledAccount() {
    var user = legacy();
    try {
      String replacement = new Password().encode("Changed password 123");
      jdbc.update(
          "UPDATE web_user SET password_hash=?,auth_version=auth_version+1 WHERE id=?",
          replacement,
          user.id());
      assertThrows(ApiException.class, () -> accounts.upgradePasswordAfterLogin(user, "password"));
      assertEquals(replacement, users.loadUserByUsername(user.getUsername()).getPassword());
      jdbc.update(
          "UPDATE web_user SET password_hash=?,auth_version=?,enabled=FALSE WHERE id=?",
          LEGACY,
          user.authVersion(),
          user.id());
      assertThrows(ApiException.class, () -> accounts.upgradePasswordAfterLogin(user, "password"));
      assertEquals(LEGACY, users.loadUserByUsername(user.getUsername()).getPassword());
    } finally {
      jdbc.update("DELETE FROM web_user WHERE id=?", user.id());
    }
  }
}
