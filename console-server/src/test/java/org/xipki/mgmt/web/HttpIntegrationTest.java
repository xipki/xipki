// License Apache License 2.0

package org.xipki.mgmt.web;

import static org.junit.jupiter.api.Assertions.*;

import java.net.*;
import java.net.http.*;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.*;
import org.apache.catalina.startup.Tomcat;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.xipki.mgmt.web.Main.LiteServlet;
import org.xipki.mgmt.web.audit.*;
import org.xipki.mgmt.web.controller.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.db.*;
import org.xipki.mgmt.web.dto.ApiResponse;
import org.xipki.mgmt.web.security.*;

/**
 * Real Tomcat, HTTP cookies/multipart, JDBC identities and audit; no production CA mutations.
 *
 * @author palos
 */
class HttpIntegrationTest {
  @TempDir Path directory;
  private Jdbc jdbc;
  private Tomcat server;
  private HttpClient browser;
  private String base;
  private final AtomicReference<String> failingAudit = new AtomicReference<>();
  private final AtomicInteger mutations = new AtomicInteger();
  private String username;
  private static final String PASSWORD = "Http test original password 42!";

  @BeforeEach
  void start() throws Exception {
    String url = System.getenv("WEB_LITE_TEST_DB_URL");
    if (Boolean.getBoolean("lite.db.required")) {
      assertNotNull(url);
    }
    Assumptions.assumeTrue(url != null);
    assertTrue(
        url.matches("jdbc:mariadb://(?:127\\.0\\.0\\.1|localhost):[0-9]+/xipki_web_lite_tests"));
    var source = new DatabaseSource(url, "root", System.getenv("WEB_LITE_TEST_DB_PASSWORD"));
    new WebSchemaInitializer(source, "lite-bootstrap", "lite bootstrap test password")
        .ensureCurrent();
    jdbc = new Jdbc(source);
    var transactions = new Transactions(jdbc);
    var password = new Password();
    username = "http-" + UUID.randomUUID().toString().substring(0, 8);
    long userId =
        jdbc.insert(
            "INSERT INTO web_user(username,password_hash,display_name,password_change_required)"
                + " VALUES (?,?,?,TRUE)",
            username,
            password.encode(PASSWORD),
            "HTTP user");
    jdbc.update(
        "INSERT INTO web_role_binding(user_id,role_name,scope_type,all_profiles) VALUES"
            + " (?,'CERT_REQUESTER','ALL_CAS',TRUE)",
        userId);
    var audit =
        new AuditService(jdbc) {
          @Override
          public void record(AuditEvent event) {
            if (event.result().equals(failingAudit.get())) {
              throw new IllegalStateException("Test audit unavailable");
            }
            if ("TARGET_ATTEMPT".equals(failingAudit.get())
                && event.result().equals("ATTEMPT")
                && event.resourceId().contains("ca=")) {
              throw new IllegalStateException("Test enriched audit unavailable");
            }
            super.record(event);
          }
        };
    var users = new WebUserDetailsService(jdbc);
    var sessions = new SessionManager(jdbc, users, new Config(Map.of()), audit);
    var accounts = new AccountService(jdbc, password, users, audit, transactions);
    Routes routes = new Routes(new AuditTargetCapture(audit));
    new IdentityRoutes(
            new AuthController(
                users, password, sessions, accounts, new LoginThrottle(jdbc, transactions)),
            null,
            null,
            null,
            sessions)
        .register(routes);
    routes.add("GET", "/health/live", r -> Map.of("status", "UP"));
    routes.add("GET", "/health/ready", r -> Map.of("status", "UP"));
    routes.add(
        "POST",
        "/api/cert/enroll",
        r -> {
          String ca = r.required("ca");
          byte[] bytes = r.upload("csr").getBytes();
          mutations.incrementAndGet();
          return ApiResponse.ok(Map.of("ca", ca, "size", bytes.length));
        });
    server = Main.server(0, directory, new LiteServlet(routes, sessions, audit));
    server.start();
    base = "http://127.0.0.1:" + server.getConnector().getLocalPort();
    CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
    browser = HttpClient.newBuilder().cookieHandler(cookies).build();
  }

  @AfterEach
  void stop() throws Exception {
    if (server != null) {
      server.stop();
      server.destroy();
    }
    RequestContext.clear();
  }

  @Test
  void anonymousBootstrapCsrfForcedPasswordAndSessionRevocation() throws Exception {
    assertEquals(401, get("/api/auth/me").statusCode());
    assertEquals(200, get("/health/live").statusCode());
    assertEquals(200, get("/").statusCode());
    assertEquals(404, get("/assets/does-not-exist.js").statusCode());
    String credentials = Json.write(Map.of("username", username, "password", PASSWORD));
    assertEquals(403, post("/api/auth/login", credentials, null).statusCode());
    String csrf = csrf();
    assertEquals(403, post("/api/auth/login", credentials, "wrong").statusCode());
    assertEquals(200, post("/api/auth/login", credentials, csrf).statusCode());
    var me = get("/api/auth/me");
    assertEquals(200, me.statusCode());
    assertTrue(me.body().contains("\"passwordChangeRequired\":true"));
    csrf = csrf();
    assertEquals(
        403, post("/api/auth/reauth", Json.write(Map.of("password", PASSWORD)), csrf).statusCode());
    assertEquals(403, multipart("small", csrf).statusCode());
    assertEquals(0, mutations.get());
    assertEquals(
        200,
        post(
                "/api/auth/password",
                Json.write(
                    Map.of(
                        "currentPassword", PASSWORD, "newPassword", "Changed HTTP password 42!")),
                csrf)
            .statusCode());
    assertEquals(401, get("/api/auth/me").statusCode());
    assertEquals(
        200,
        post(
                "/api/auth/login",
                Json.write(Map.of("username", username, "password", "Changed HTTP password 42!")),
                csrf())
            .statusCode());
    assertEquals(400, put("/api/auth/profile", "{\"displayName\":1}", csrf()).statusCode());
    assertEquals(400, put("/api/auth/profile", "{\"typo\":null}", csrf()).statusCode());
    assertEquals(
        200, put("/api/auth/profile", "{\"displayName\":\"测试 HTTP\"}", csrf()).statusCode());
    assertEquals(
        "测试 HTTP",
        jdbc.queryForObject(
            "SELECT display_name FROM web_user WHERE username=?", String.class, username));
    var upload = multipart("test-csr", csrf());
    assertEquals(200, upload.statusCode(), upload.body());
    assertTrue(upload.body().contains("\"size\":8"));
    assertEquals(413, multipart("x".repeat(2 * 1024 * 1024 + 1), csrf()).statusCode());
    assertEquals(1, mutations.get());
    jdbc.update("UPDATE web_user SET auth_version=auth_version+1 WHERE username=?", username);
    assertEquals(401, get("/api/auth/me").statusCode());
  }

  @Test
  void auditFailurePreventsMutationAndOverridesResponseBeforeCommit() throws Exception {
    jdbc.update("UPDATE web_user SET password_change_required=FALSE WHERE username=?", username);
    assertEquals(
        200,
        post(
                "/api/auth/login",
                Json.write(Map.of("username", username, "password", PASSWORD)),
                csrf())
            .statusCode());
    String csrf = csrf();
    failingAudit.set("ATTEMPT");
    assertEquals(503, multipart("test", csrf).statusCode());
    assertEquals(0, mutations.get());
    failingAudit.set("TARGET_ATTEMPT");
    assertEquals(503, multipart("test", csrf).statusCode());
    assertEquals(0, mutations.get());
    failingAudit.set("SUCCESS");
    var result = multipart("test", csrf);
    assertEquals(503, result.statusCode());
    assertTrue(result.body().contains("verify operation result"));
    assertEquals(1, mutations.get());
    failingAudit.set(null);
    assertEquals(200, get("/api/auth/me").statusCode());
    assertTrue(
        jdbc.queryForObject(
                "SELECT COUNT(*) FROM web_audit_event WHERE actor_username=? AND result='ATTEMPT'",
                Integer.class,
                username)
            > 0);
    assertTrue(
        jdbc.queryForObject(
                "SELECT COUNT(*) FROM web_audit_event WHERE actor_username=? AND result='ATTEMPT'"
                    + " AND resource_id LIKE '%ca=example%' AND resource_id LIKE"
                    + " '%profile=server%'",
                Integer.class, username)
            > 0);
  }

  @Test
  void anonymousBootstrapDoesNotGrowSessionOrAuditTables() throws Exception {
    long sessionsBefore = jdbc.queryForObject("SELECT COUNT(*) FROM lite_session", Long.class);
    long auditBefore = jdbc.queryForObject("SELECT COUNT(*) FROM web_audit_event", Long.class);
    HttpClient anonymous = HttpClient.newHttpClient();
    for (int i = 0; i < 25; i++) {
      var response =
          anonymous.send(
              HttpRequest.newBuilder(URI.create(base + "/api/auth/csrf")).GET().build(),
              HttpResponse.BodyHandlers.ofString());
      assertEquals(200, response.statusCode());
      assertNotNull(Json.read(response.body(), Map.class).get("token"));
    }
    assertEquals(
        sessionsBefore, jdbc.queryForObject("SELECT COUNT(*) FROM lite_session", Long.class));
    assertEquals(
        auditBefore, jdbc.queryForObject("SELECT COUNT(*) FROM web_audit_event", Long.class));
  }

  @Test
  void multipartPartCountIsBoundedBeforeDispatch() throws Exception {
    jdbc.update("UPDATE web_user SET password_change_required=FALSE WHERE username=?", username);
    assertEquals(
        200,
        post(
                "/api/auth/login",
                Json.write(Map.of("username", username, "password", PASSWORD)),
                csrf())
            .statusCode());
    var body = new StringBuilder();
    for (int i = 0; i < 20; i++) {
      String field = i == 0 ? "ca" : i == 1 ? "profile" : i == 2 ? "csr" : "extra" + i;
      body.append("--boundary\r\nContent-Disposition: form-data; name=\"")
          .append(field)
          .append("\"\r\n\r\nexample\r\n");
    }
    body.append("--boundary--\r\n");
    assertEquals(
        413,
        send(
                "POST",
                "/api/cert/enroll",
                body.toString(),
                csrf(),
                "multipart/form-data; boundary=boundary")
            .statusCode());
    assertEquals(0, mutations.get());
  }

  private HttpResponse<String> get(String path) throws Exception {
    return browser.send(
        HttpRequest.newBuilder(URI.create(base + path)).GET().build(),
        HttpResponse.BodyHandlers.ofString());
  }

  private String csrf() throws Exception {
    return (String) Json.read(get("/api/auth/csrf").body(), Map.class).get("token");
  }

  private HttpResponse<String> post(String path, String body, String csrf) throws Exception {
    return send("POST", path, body, csrf, "application/json");
  }

  private HttpResponse<String> put(String path, String body, String csrf) throws Exception {
    return send("PUT", path, body, csrf, "application/json");
  }

  private HttpResponse<String> multipart(String content, String csrf) throws Exception {
    String body =
        "--boundary\r\n"
            + "Content-Disposition: form-data; name=\"ca\"\r\n\r\n"
            + "example\r\n"
            + "--boundary\r\n"
            + "Content-Disposition: form-data; name=\"profile\"\r\n\r\n"
            + "server\r\n"
            + "--boundary\r\n"
            + "Content-Disposition: form-data; name=\"csr\"; filename=\"request.pem\"\r\n"
            + "Content-Type: application/octet-stream\r\n\r\n"
            + content
            + "\r\n--boundary--\r\n";
    return send("POST", "/api/cert/enroll", body, csrf, "multipart/form-data; boundary=boundary");
  }

  private HttpResponse<String> send(
      String method, String path, String body, String csrf, String type) throws Exception {
    var request =
        HttpRequest.newBuilder(URI.create(base + path))
            .header("Content-Type", type)
            .method(method, HttpRequest.BodyPublishers.ofString(body));
    if (csrf != null) {
      request.header("X-CSRF-TOKEN", csrf);
    }
    return browser.send(request.build(), HttpResponse.BodyHandlers.ofString());
  }
}
