// License Apache License 2.0

package org.xipki.mgmt.web;

import jakarta.servlet.MultipartConfigElement;
import jakarta.servlet.http.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.*;
import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.mgmt.web.audit.*;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.CaManager;
import org.xipki.mgmt.web.ca.OfficialCaMgmtClientAdapter;
import org.xipki.mgmt.web.controller.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.core.AccessDeniedException;
import org.xipki.mgmt.web.core.Jdbc.DataAccessException;
import org.xipki.mgmt.web.core.Jdbc.DuplicateKeyException;
import org.xipki.mgmt.web.db.*;
import org.xipki.mgmt.web.security.*;
import org.xipki.mgmt.web.service.*;

/**
 * Lightweight entry point: one Servlet, explicit routes, no framework lifecycle.
 *
 * @author palos
 */
public final class Main {
  private static final Logger LOG = LoggerFactory.getLogger(Main.class);

  public static void main(String[] args) throws Exception {
    Config config = Config.system();
    WebDatabaseProperties database = WebDatabaseProperties.from(config);
    DatabaseSource source =
        new DatabaseSource(database.url(), database.username(), database.password());
    String admin = config.getProperty("WEB_ADMIN_USERNAME", "admin"),
        password = secret(config, "WEB_ADMIN_PASSWORD", "WEB_ADMIN_PASSWORD_FILE");
    if (admin.isBlank()) {
      admin = "admin";
    }
    if (admin.codePointCount(0, admin.length()) > 100
        || admin.codePoints().anyMatch(Character::isISOControl)
        || password.getBytes(StandardCharsets.UTF_8).length > 72) {
      throw new IllegalArgumentException("Invalid bootstrap credentials");
    }
    new WebSchemaInitializer(source, admin, password).ensureCurrent();
    Jdbc jdbc = new Jdbc(source);
    Transactions transactions = new Transactions(jdbc);
    AuditService audit = new AuditService(jdbc);
    WebUserDetailsService users = new WebUserDetailsService(jdbc);
    SessionManager sessions = new SessionManager(jdbc, users, config, audit);
    Password passwords = new Password();
    LoginThrottle throttle = new LoginThrottle(jdbc, transactions);
    AccountService accounts = new AccountService(jdbc, passwords, users, audit, transactions);
    RoleService roleService = new RoleService(jdbc, transactions, audit);
    RoleCatalog roleCatalog = new RoleCatalog(jdbc);
    AuthController auth = new AuthController(users, passwords, sessions, accounts, throttle, config);
    CaManager client = caClient(config);
    CaManagementService ca = new CaManagementService(client);
    AccessControl access = new AccessControl(ca);
    CaEnrollmentRepository repository = new CaEnrollmentRepository(jdbc);
    CaConfigurationService configuration =
        new CaConfigurationService(ca, new CaConfigurationMapper(), new CaKeyMaterialService());
    QuickStartService quickStart =
        new QuickStartService(ca, configuration, config);
    EnrollmentKeyStore keys =
        new EnrollmentKeyStore(
            config.getProperty("WEB_ENROLLMENT_KEY_FILE", ""),
            config.getProperty("WEB_ENROLLMENT_KEY_DIR", ""));
    if (!config.getProperty("WEB_ENROLLMENT_KEY_FILE", "").isBlank()
        || !config.getProperty("WEB_ENROLLMENT_KEY_DIR", "").isBlank()) {
      keys.requireAvailable();
    }
    CaEnrollmentService enrollment =
        new CaEnrollmentService(
            repository,
            keys,
            ca,
            access,
            configuration,
            new CaKeyMaterialService(),
            new CaCertificateValidationService(),
            CaEnrollmentSubjectOrder.parseOrder(config.getProperty("XIPKI_CA_RDN_ORDER")));
    CertificateOwnership ownership = new CertificateOwnership(jdbc);
    AuditTargetCapture capture = new AuditTargetCapture(audit);
    Routes routes = new Routes(capture);
    new IdentityRoutes(
            auth,
            new UserController(accounts, access, ca),
            new RoleController(roleService, roleCatalog),
            new AuditController(audit),
            sessions)
        .register(routes);
    CaRoutes.register(
        routes,
        ca,
        configuration,
        quickStart,
        access,
        accounts,
        repository,
        enrollment,
        ownership,
        capture);
    routes.add("GET", "/health/live", request -> Map.of("status", "UP"));
    WebDatabaseHealth health = new WebDatabaseHealth(jdbc);
    ReadinessProbe readiness =
        new ReadinessProbe(health::isReady, ca::isReady, Duration.ofSeconds(5), System::nanoTime);
    routes.add(
        "GET",
        "/health/ready",
        request -> {
          if (!readiness.isReady()) {
            throw new ApiException(503, "Service unavailable");
          }
          return Map.of("status", "UP");
        });
    LiteServlet servlet = new LiteServlet(routes, sessions, audit, ca);
    int port = config.getProperty("SERVER_PORT", Integer.class, 8080);
    Path base = Path.of(config.getProperty("SERVER_BASE_DIR", "/tmp/xipki-console"));
    Tomcat tomcat = server(config, port, base, servlet);
    Runtime.getRuntime()
        .addShutdownHook(
            new Thread(
                () -> {
                  try {
                    tomcat.stop();
                    tomcat.destroy();
                  } catch (Exception ex) {
                    LOG.warn("Failed to stop the Console server cleanly", ex);
                  }
                }));
    tomcat.start();
    Thread cleanup =
        new Thread(
            () -> {
              while (!Thread.currentThread().isInterrupted()) {
                try {
                  Thread.sleep(60_000);
                  sessions.cleanup();
                } catch (InterruptedException ex) {
                  Thread.currentThread().interrupt();
                } catch (RuntimeException ex) {
                  LOG.warn("Session cleanup failed; retrying next interval", ex);
                }
              }
            },
            "lite-session-cleanup");
    cleanup.setDaemon(true);
    cleanup.start();
    tomcat.getServer().await();
  }

  static String secret(Config config, String key, String fileKey) {
    String inline = config.getProperty(key),
        file = fileKey == null ? null : config.getProperty(fileKey);
    if (inline != null && file != null) {
      throw new IllegalArgumentException("Configure only one secret source");
    }
    if (inline == null && file != null) {
      try {
        inline = Files.readString(Path.of(file), StandardCharsets.UTF_8);
        if (inline.endsWith("\r\n")) {
          inline = inline.substring(0, inline.length() - 2);
        } else if (inline.endsWith("\n")) {
          inline = inline.substring(0, inline.length() - 1);
        }
      } catch (IOException ex) {
        throw new IllegalStateException("Unable to read secret", ex);
      }
    }
    if (inline == null
        || inline.isEmpty()
        || inline.indexOf('\n') >= 0
        || inline.indexOf('\r') >= 0
        || inline.indexOf('\0') >= 0) {
      throw new IllegalArgumentException("Required secret is invalid");
    }
    return inline;
  }

  /** Creates the authenticated management adapter used by all Console CA operations. */
  private static CaManager caClient(Config config) throws Exception {
    Path dir = Path.of(config.getProperty("XIPKI_CLIENT_DIR", "/run/xipki-client"));
    String url = config.getProperty("XIPKI_CA_URL", "https://ca:8443/ca/mgmt");
    if (!url.startsWith("https://")) {
      throw new IllegalArgumentException("CA management requires HTTPS");
    }
    String keystore =
        config.getProperty("XIPKI_CLIENT_KEYSTORE", dir.resolve("client.p12").toString());
    String trust =
        config.getProperty(
            "XIPKI_CLIENT_TRUSTANCHORS", dir.resolve("trustanchors.pem").toString());
    String passwordFile =
        config.getProperty("XIPKI_CLIENT_PASSWORD_FILE", dir.resolve("password").toString());
    // Internal client credentials are deployment Secrets; unlike non-secret connection settings,
    // the password deliberately has no inline environment-variable form.
    String password = secret(new Config(Map.of("file", passwordFile)), "value", "file");
    char[] secret = password.toCharArray();
    try {
      return new OfficialCaMgmtClientAdapter(
          url, Path.of(keystore), secret, Path.of(trust));
    } finally {
      Arrays.fill(secret, '\0');
    }
  }

  private Main() {}

  /**
   * Creates the Console listener and enables PEM-based TLS when requested. HTTP remains available
   * to embedded tests, while the packaged Compose deployment explicitly enables HTTPS.
   */
  static Tomcat server(Config config, int port, Path base, HttpServlet servlet) throws IOException {
    Tomcat tomcat = server(port, base, servlet);
    if (!Boolean.parseBoolean(config.getProperty("SERVER_TLS_ENABLED", "false"))) {
      return tomcat;
    }

    String certificate = requiredPath(config, "SERVER_TLS_CERT_FILE");
    String privateKey = requiredPath(config, "SERVER_TLS_KEY_FILE");
    Connector connector = tomcat.getConnector();
    connector.setScheme("https");
    connector.setSecure(true);
    connector.setProperty("SSLEnabled", "true");
    SSLHostConfig ssl = new SSLHostConfig();
    ssl.setEnabledProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
    String clientCa = config.getProperty("SERVER_TLS_CLIENT_CA_FILE");
    if (clientCa != null && !clientCa.isBlank()) {
      ssl.setTrustStore(clientTrustStore(Path.of(clientCa)));
      ssl.setCertificateVerification("optional");
    }
    SSLHostConfigCertificate identity =
        new SSLHostConfigCertificate(ssl, SSLHostConfigCertificate.Type.UNDEFINED);
    identity.setCertificateFile(certificate);
    identity.setCertificateKeyFile(privateKey);
    ssl.addCertificate(identity);
    connector.addSslHostConfig(ssl);
    return tomcat;
  }

  /** Validates configured TLS files early so startup fails with an actionable error. */
  private static String requiredPath(Config config, String key) {
    String value = config.getProperty(key);
    if (value == null || value.isBlank() || !Files.isReadable(Path.of(value))) {
      throw new IllegalArgumentException(key + " must name a readable file");
    }
    return value;
  }

  /** Builds an in-memory trust store from the deployment's PEM client CA bundle. */
  private static KeyStore clientTrustStore(Path file) {
    if (!Files.isReadable(file)) {
      throw new IllegalArgumentException("SERVER_TLS_CLIENT_CA_FILE must name a readable file");
    }
    try (InputStream input = Files.newInputStream(file)) {
      KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
      trust.load(null, null);
      int index = 0;
      for (var certificate : CertificateFactory.getInstance("X.509").generateCertificates(input)) {
        trust.setCertificateEntry("client-ca-" + index++, certificate);
      }
      if (index == 0) {
        throw new IllegalArgumentException("Client CA bundle contains no certificates");
      }
      return trust;
    } catch (Exception ex) {
      throw new IllegalArgumentException("Unable to load SERVER_TLS_CLIENT_CA_FILE", ex);
    }
  }

  /** Creates the bounded HTTP connector used by tests and as the base for the TLS listener. */
  static Tomcat server(int port, Path base, HttpServlet servlet) throws IOException {
    Files.createDirectories(base);
    Tomcat tomcat = new Tomcat();
    tomcat.setBaseDir(base.toString());
    tomcat.setPort(port);
    var connector = tomcat.getConnector();
    connector.setProperty("maxPostSize", Integer.toString(8 * 1024 * 1024));
    connector.setProperty("maxParameterCount", "1000");
    connector.setProperty("maxThreads", "64");
    connector.setProperty("connectionTimeout", "20000");
    Context context = tomcat.addContext("", base.toAbsolutePath().toString());
    context.setParentClassLoader(Main.class.getClassLoader());
    // Tomcat may silently ignore parts beyond its limit; allow one excess part so
    // the servlet can reject the whole request instead of acting on truncated input.
    var wrapper = Tomcat.addServlet(context, "xipki-lite", servlet);
    wrapper.setMultipartConfigElement(
        new MultipartConfigElement(base.toString(), 2 * 1024 * 1024, 8 * 1024 * 1024, 1024 * 1024));
    connector.setProperty("maxPartCount", "17");
    connector.setProperty("maxPartHeaderSize", "1024");
    connector.setProperty("maxConnections", "256");
    context.addServletMappingDecoded("/*", "xipki-lite");
    return tomcat;
  }

  static final class LiteServlet extends HttpServlet {
    private final Routes routes;
    private final SessionManager sessions;
    private final AuditFilter audit;
    private final CaManagementService ca;

    LiteServlet(Routes routes, SessionManager sessions, AuditService service) {
      this(routes, sessions, service, null);
    }

    LiteServlet(
        Routes routes, SessionManager sessions, AuditService service, CaManagementService ca) {
      this.routes = routes;
      this.sessions = sessions;
      this.audit = new AuditFilter(service);
      this.ca = ca;
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
      RequestIdFilter.apply(req, resp);
      resp.setHeader("X-Content-Type-Options", "nosniff");
      resp.setHeader("X-Frame-Options", "DENY");
      resp.setHeader("Referrer-Policy", "no-referrer");
      String path = req.getRequestURI();
      boolean api = path.startsWith("/api/");
      if (!api) {
        try {
          if (path.startsWith("/health/")) {
            write(resp, routes.dispatch(req, resp));
          } else {
            staticResource(req, resp);
          }
        } catch (Exception ex) {
          Reply<?> error = error(ex, ca);
          write(resp, error);
        }
        return;
      }
      resp.setHeader("Cache-Control", "no-store");
      long start = System.nanoTime();
      boolean begun = false;
      Object body = null;
      Throwable failure = null;
      Reply<?> result;
      try {
        WebPrincipal principal = sessions.authenticate(req, resp);
        RequestContext.bind(req, principal);
        start = audit.begin(req);
        begun = true;
        if (req.getContentLengthLong() > 8 * 1024 * 1024) {
          throw new ApiException(413, "Request too large");
        }
        var rule = ManagementApiPolicy.match(req.getMethod(), path);
        if (rule == null) {
          throw new AccessDeniedException("Permission denied");
        }
        if (!rule.publicEntry() && principal == null) {
          throw new ApiException(401, "Not authenticated");
        }
        if (!ManagementApiPolicy.authorized(req, principal)) {
          throw new AccessDeniedException("Permission denied");
        }
        if (!Set.of("GET", "HEAD", "OPTIONS").contains(req.getMethod())) {
          sessions.requireCsrf(req);
        }
        if (req.getContentType() != null
            && req.getContentType().toLowerCase(Locale.ROOT).startsWith("multipart/form-data")) {
          try {
            if (req.getParts().size() > 16) {
              throw new ApiException(413, "Too many upload fields");
            }
          } catch (IllegalStateException ex) {
            throw new ApiException(413, "Uploaded material or request exceeds the size limit");
          }
        }
        body = routes.dispatch(req, resp);
        result = body instanceof Reply<?> reply ? reply : Reply.ok(body);
      } catch (Exception ex) {
        failure = ex;
        result = error(ex, ca);
      }
      try {
        if (begun) {
          try {
            audit.finish(req, result.status(), result.body(), failure, start);
          } catch (Exception ex) {
            result =
                Reply.status(503)
                    .body(
                        Map.of(
                            "error",
                            "Audit storage temporarily unavailable; verify operation result before"
                                + " retry"));
          }
        }
        // Encode before committing a successful HTTP result; codec errors must not emit partial
        // JSON.
        byte[] encoded =
            result.body() instanceof byte[] bytes
                ? bytes
                : result.body() == null ? new byte[0] : Json.bytes(result.body());
        resp.setStatus(result.status());
        result.headers().forEach(resp::setHeader);
        if (resp.getContentType() == null) {
          resp.setContentType(
              result.body() instanceof byte[]
                  ? "application/octet-stream"
                  : "application/json;charset=UTF-8");
        }
        resp.getOutputStream().write(encoded);
      } finally {
        RequestContext.clear();
      }
    }

    static Reply<?> error(Exception ex, CaManagementService ca) {
      int status = 500;
      String message = "Internal server error";
      if (ex instanceof ApiException api) {
        status = api.status();
        message = api.getMessage();
      } else if (ex instanceof DuplicateKeyException) {
        status = 409;
        message = "Resource name already exists";
      } else if (ex instanceof DataAccessException) {
        status = 503;
        message = "Web database temporarily unavailable";
      } else if (ex instanceof RoleValidationException) {
        status = 400;
        message = ex.getMessage();
      } else if (ex instanceof IllegalArgumentException || ex instanceof ClassCastException) {
        status = 400;
        message = "Invalid request fields or format";
      } else if (ex instanceof CaMgmtException) {
        boolean transport = false;
        for (Throwable cause = ex; cause != null; cause = cause.getCause()) {
          if (cause instanceof IOException) {
            transport = true;
            break;
          }
        }
        status = transport || (ca != null && !ca.isReady()) ? 503 : 400;
        message =
            transport
                ? "CA response unavailable; operation may have completed; verify operation result"
                    + " before retry"
                : status == 503
                    ? "CA service temporarily unavailable"
                    : "CA management request failed";
      } else {
        LOG.error("Unexpected request error ({})", ex.getClass().getSimpleName());
      }
      return Reply.status(status)
          .body(Map.of("error", message == null ? "Request failed" : message));
    }

    private static int write(HttpServletResponse response, Object value) throws IOException {
      if (value instanceof Reply<?> reply) {
        response.setStatus(reply.status());
        reply.headers().forEach(response::setHeader);
        value = reply.body();
      }
      if (response.getStatus() == 204 || value == null) {
        return response.getStatus() == 0 ? 204 : response.getStatus();
      }
      if (value instanceof byte[] bytes) {
        if (response.getContentType() == null) {
          response.setContentType("application/octet-stream");
        }
        response.getOutputStream().write(bytes);
        return response.getStatus() == 0 ? 200 : response.getStatus();
      }
      response.setContentType("application/json;charset=UTF-8");
      response.getOutputStream().write(Json.bytes(value));
      return response.getStatus() == 0 ? 200 : response.getStatus();
    }

    private static int staticResource(HttpServletRequest request, HttpServletResponse response)
        throws IOException {
      if (!Set.of("GET", "HEAD").contains(request.getMethod())) {
        writeError(response, 405, "Method not allowed");
        return 405;
      }
      String path = request.getRequestURI();
      if (path.contains("..") || path.indexOf('\\') >= 0) {
        writeError(response, 404, "Not found");
        return 404;
      }
      if (path.equals("/")) {
        path = "/index.html";
      }
      String resource = "/static" + (path.equals("/index.html") ? "/index.html" : path);
      InputStream stream = Main.class.getResourceAsStream(resource);
      if (stream == null && !path.substring(path.lastIndexOf('/') + 1).contains(".")) {
        stream = Main.class.getResourceAsStream("/static/index.html");
        path = "/index.html";
      }
      if (stream == null) {
        writeError(response, 404, "Not found");
        return 404;
      }
      String type =
          path.endsWith(".js")
              ? "application/javascript"
              : path.endsWith(".css")
                  ? "text/css"
                  : path.endsWith(".svg") ? "image/svg+xml" : "text/html;charset=UTF-8";
      response.setContentType(type);
      response.setHeader(
          "Cache-Control",
          path.equals("/index.html") ? "no-cache" : "public,max-age=31536000,immutable");
      try (InputStream content = stream) {
        if (!request.getMethod().equals("HEAD")) {
          content.transferTo(response.getOutputStream());
        }
      }
      return 200;
    }

    private static void writeError(HttpServletResponse response, int status, String message)
        throws IOException {
      if (response.isCommitted()) {
        return;
      }
      response.resetBuffer();
      response.setStatus(status);
      response.setContentType("application/json;charset=UTF-8");
      response
          .getOutputStream()
          .write(Json.bytes(Map.of("error", message == null ? "Request failed" : message)));
    }
  }
}
