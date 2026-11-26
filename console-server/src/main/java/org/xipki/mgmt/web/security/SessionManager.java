// License Apache License 2.0

package org.xipki.mgmt.web.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.xipki.mgmt.web.audit.*;
import org.xipki.mgmt.web.core.*;

/**
 * Opaque bearer tokens are only sent to the browser; the database stores their SHA-256 digest.
 *
 * @author palos
 */
public final class SessionManager {
  public static final String COOKIE = "LITE_SESSION",
      SESSION = SessionManager.class.getName() + ".session";
  private static final long IDLE = 1_800_000;
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final long BOOTSTRAP_LIFETIME = 600_000;
  private final byte[] bootstrapKey = new byte[32];
  private final Jdbc jdbc;
  private final WebUserDetailsService users;
  private final AuditService audit;
  private final Transactions transactions;
  private final boolean secure;

  private static final class Session {
    final SessionManager owner;
    final String hash, csrf;
    final Long userId;
    final long authVersion;
    long recentAt;

    Session(
        SessionManager owner,
        String hash,
        String csrf,
        Long userId,
        long authVersion,
        long recentAt) {
      this.owner = owner;
      this.hash = hash;
      this.csrf = csrf;
      this.userId = userId;
      this.authVersion = authVersion;
      this.recentAt = recentAt;
    }
  }

  public SessionManager(Jdbc jdbc, WebUserDetailsService users, Config config) {
    this(jdbc, users, config, new AuditService(jdbc));
  }

  public SessionManager(Jdbc jdbc, WebUserDetailsService users, Config config, AuditService audit) {
    this.jdbc = jdbc;
    this.users = users;
    this.audit = audit;
    this.transactions = new Transactions(jdbc);
    secure = Boolean.parseBoolean(config.getProperty("SESSION_COOKIE_SECURE", "false"));
    RANDOM.nextBytes(bootstrapKey);
  }

  public WebPrincipal authenticate(HttpServletRequest request, HttpServletResponse response) {
    request.removeAttribute(SESSION);
    String bearer = cookie(request);
    if (bearer == null) {
      return null;
    }
    if (bearer.startsWith("b.")) {
      if (validBootstrap(bearer)) {
        request.setAttribute(SESSION, new Session(this, null, bearer, null, 0, 0));
      } else {
        clearCookie(response);
      }
      return null;
    }
    String digest = hash(bearer);
    var rows =
        jdbc.query(
            "SELECT user_id,auth_version,csrf_token,last_access_ms,recent_auth_ms FROM lite_session"
                + " WHERE token_hash=?",
            (rs, n) ->
                new Object[] {
                  rs.getObject("user_id"),
                  rs.getLong("auth_version"),
                  rs.getString("csrf_token"),
                  rs.getLong("last_access_ms"),
                  rs.getLong("recent_auth_ms")
                },
            digest);
    if (rows.isEmpty()) {
      clearCookie(response);
      return null;
    }
    Object[] row = rows.get(0);
    long now = System.currentTimeMillis();
    if (expired((Long) row[3], now)) {
      clearCookie(response);
      return null;
    }
    long id = ((Number) row[0]).longValue();
    var names = jdbc.queryForList("SELECT username FROM web_user WHERE id=?", String.class, id);
    if (names.isEmpty()) {
      invalidate(digest, response);
      return null;
    }
    WebPrincipal principal = users.loadUserByUsername(names.get(0));
    if (!principal.isEnabled() || principal.authVersion() != (Long) row[1]) {
      invalidate(digest, response);
      return null;
    }
    // Conditional update prevents a concurrent revocation from recreating or extending the session.
    if (jdbc.update(
            "UPDATE lite_session s SET last_access_ms=? WHERE token_hash=? AND last_access_ms>? AND"
                + " EXISTS (SELECT 1 FROM web_user u WHERE u.id=s.user_id AND u.enabled=TRUE AND"
                + " u.auth_version=s.auth_version)",
            now,
            digest,
            now - IDLE)
        != 1) {
      clearCookie(response);
      return null;
    }
    request.setAttribute(
        SESSION, new Session(this, digest, (String) row[2], id, (Long) row[1], (Long) row[4]));
    return principal;
  }

  public String csrf(HttpServletRequest request, HttpServletResponse response) {
    Session state = state(request);
    if (state == null) {
      String value = "b." + Long.toString(System.currentTimeMillis(), 36) + "." + token();
      value += "." + bootstrapSignature(value);
      state = new Session(this, null, value, null, 0, 0);
      request.setAttribute(SESSION, state);
      setCookie(response, value, -1);
    }
    return state.csrf;
  }

  public void requireCsrf(HttpServletRequest request) {
    Session state = state(request);
    String provided = request.getHeader("X-CSRF-TOKEN");
    if (state == null
        || provided == null
        || provided.length() > 128
        || !MessageDigest.isEqual(
            state.csrf.getBytes(StandardCharsets.US_ASCII),
            provided.getBytes(StandardCharsets.UTF_8))) {
      throw new AccessDeniedException("Invalid CSRF token");
    }
  }

  public void login(
      HttpServletRequest request, HttpServletResponse response, WebPrincipal principal) {
    if (principal == null || !principal.isEnabled()) {
      throw new ApiException(401, "Invalid credentials");
    }
    transactions.executeWithoutResult(
        status -> {
          // Lock the account while creating a session so invalidation cannot miss the new session.
          var versions =
              jdbc.queryForList(
                  "SELECT auth_version FROM web_user WHERE id=? AND enabled=TRUE FOR UPDATE",
                  Long.class,
                  principal.id());
          if (versions.isEmpty() || versions.get(0) != principal.authVersion()) {
            throw new ApiException(401, "Invalid credentials");
          }
          var previous = state(request);
          if (previous != null && previous.hash != null) {
            jdbc.update("DELETE FROM lite_session WHERE token_hash=?", previous.hash);
          }
          create(request, response, principal);
        });
    RequestContext.bind(request, principal);
  }

  public void logout(HttpServletRequest request, HttpServletResponse response) {
    Session state = state(request);
    if (state != null && state.hash != null) {
      jdbc.update("DELETE FROM lite_session WHERE token_hash=?", state.hash);
    }
    request.removeAttribute(SESSION);
    clearCookie(response);
  }

  private Session create(
      HttpServletRequest request, HttpServletResponse response, WebPrincipal principal) {
    Objects.requireNonNull(principal, "principal");
    String bearer = token(), digest = hash(bearer), csrf = token();
    long now = System.currentTimeMillis();
    Session state =
        new Session(
            this,
            digest,
            csrf,
            principal.id(),
            principal.authVersion(),
            now);
    jdbc.update(
        "INSERT INTO"
            + " lite_session(token_hash,user_id,auth_version,csrf_token,created_ms,"
            + "last_access_ms,recent_auth_ms)"
            + " VALUES (?,?,?,?,?,?,?)",
        digest,
        state.userId,
        state.authVersion,
        csrf,
        now,
        now,
        state.recentAt);
    request.setAttribute(SESSION, state);
    setCookie(response, bearer, -1);
    return state;
  }

  public static void confirm(HttpServletRequest request) {
    Session state = state(request);
    if (state == null || state.userId == null) {
      throw new AccessDeniedException("Reauthentication required");
    }
    long now = System.currentTimeMillis();
    if (state.owner.jdbc.update(
            "UPDATE lite_session s SET recent_auth_ms=? WHERE token_hash=? AND last_access_ms>? AND"
                + " EXISTS (SELECT 1 FROM web_user u WHERE u.id=s.user_id AND u.enabled=TRUE AND"
                + " u.auth_version=s.auth_version)",
            now,
            state.hash,
            now - IDLE)
        != 1) {
      throw new AccessDeniedException("Session expired");
    }
    state.recentAt = now;
  }

  public static long reauthenticatedAt(HttpServletRequest request) {
    Session s = state(request);
    return s == null ? 0 : s.recentAt;
  }

  static boolean recent(long at, long now) {
    return at > 0 && at <= now && now - at <= 300_000;
  }

  static boolean expired(long accessed, long now) {
    return accessed > now || now - accessed >= IDLE;
  }

  static String token() {
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  static String hash(String token) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256")
                  .digest(token.getBytes(StandardCharsets.US_ASCII)));
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalStateException(ex);
    }
  }

  private static Session state(HttpServletRequest req) {
    Object s = req.getAttribute(SESSION);
    return s instanceof Session session ? session : null;
  }

  private void invalidate(String digest, HttpServletResponse response) {
    jdbc.update("DELETE FROM lite_session WHERE token_hash=?", digest);
    clearCookie(response);
  }

  private static String cookie(HttpServletRequest request) {
    String token = null;
    if (request.getCookies() != null) {
      for (Cookie c : request.getCookies()) {
        if (COOKIE.equals(c.getName())) {
          if (token != null
              || c.getValue().length() > 128
              || !c.getValue()
                  .matches(
                      "(?:[A-Za-z0-9_-]{43}|b\\.[a-z0-9]{1,13}\\."
                          + "[A-Za-z0-9_-]{43}\\.[A-Za-z0-9_-]{43})")) {
            return null;
          }
          token = c.getValue();
        }
      }
    }
    return token;
  }

  private void clearCookie(HttpServletResponse response) {
    setCookie(response, "", 0);
  }

  private void setCookie(HttpServletResponse response, String value, int age) {
    response.addHeader(
        "Set-Cookie",
        COOKIE
            + "="
            + value
            + "; Path=/; HttpOnly; SameSite=Lax"
            + (secure ? "; Secure" : "")
            + (age == 0 ? "; Max-Age=0" : ""));
  }

  private String bootstrapSignature(String value) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(bootstrapKey, "HmacSHA256"));
      return Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(mac.doFinal(value.getBytes(StandardCharsets.US_ASCII)));
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException(ex);
    }
  }

  private boolean validBootstrap(String value) {
    try {
      int end = value.lastIndexOf('.');
      long issued = Long.parseLong(value.substring(2, value.indexOf('.', 2)), 36),
          now = System.currentTimeMillis();
      return issued <= now
          && now - issued < BOOTSTRAP_LIFETIME
          && MessageDigest.isEqual(
              bootstrapSignature(value.substring(0, end)).getBytes(StandardCharsets.US_ASCII),
              value.substring(end + 1).getBytes(StandardCharsets.US_ASCII));
    } catch (IllegalArgumentException ex) {
      return false;
    }
  }

  /** At most 200 rows per run; audit and removal commit together. Tokens never enter logs. */
  public void cleanup() {
    transactions.executeWithoutResult(
        status -> {
          var rows =
              jdbc.queryForList(
                  "SELECT s.token_hash,u.username FROM lite_session s JOIN web_user u"
                      + " ON u.id=s.user_id WHERE s.last_access_ms<=?"
                      + " ORDER BY s.last_access_ms LIMIT 200 FOR UPDATE",
                  System.currentTimeMillis() - IDLE);
          for (var row : rows) {
            audit.record(
                new AuditEvent(
                    (String) row.get("username"),
                    null,
                    null,
                    UUID.randomUUID().toString(),
                    null,
                    null,
                    "SESSION_EXPIRED",
                    "SUCCESS",
                    null,
                    0,
                    "session",
                    (String) row.get("token_hash")));
            jdbc.update("DELETE FROM lite_session WHERE token_hash=?", row.get("token_hash"));
          }
        });
  }
}
