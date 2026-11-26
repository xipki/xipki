// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import org.xipki.mgmt.web.audit.AuditFilter;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.*;
import org.xipki.mgmt.web.dto.IdentityRequests.Reauth;
import org.xipki.mgmt.web.dto.IdentityRequests.Update;
import org.xipki.mgmt.web.security.*;
import org.xipki.mgmt.web.security.WebPrincipal.Authority;

/**
 * @author palos
 */
public final class AuthController {
  private final WebUserDetailsService users;
  private final Password passwords;
  private final SessionManager sessions;
  private final AccountService accounts;
  private final LoginThrottle throttle;
  private final String dummyHash;
  private final boolean passwordLogin;
  private final boolean certificateLogin;
  private final byte[] adminCertificateFingerprint;
  private final String adminCertificateUsername;

  public AuthController(
      WebUserDetailsService users,
      Password passwords,
      SessionManager sessions,
      AccountService accounts,
      LoginThrottle throttle) {
    this(
        users,
        passwords,
        sessions,
        accounts,
        throttle,
        new Config(Map.of("WEB_AUTH_MODE", "password")));
  }

  /**
   * Creates authentication endpoints for the configured password, client-certificate, or combined
   * mode. Certificate mode pins the bootstrap certificate instead of trusting its subject text.
   */
  public AuthController(
      WebUserDetailsService users,
      Password passwords,
      SessionManager sessions,
      AccountService accounts,
      LoginThrottle throttle,
      Config config) {
    this.users = users;
    this.passwords = passwords;
    this.sessions = sessions;
    this.accounts = accounts;
    this.throttle = throttle;
    String mode = config.getProperty("WEB_AUTH_MODE", "both").strip().toLowerCase(Locale.ROOT);
    if (!Set.of("password", "certificate", "both").contains(mode)) {
      throw new IllegalArgumentException("WEB_AUTH_MODE must be password, certificate, or both");
    }
    passwordLogin = !mode.equals("certificate");
    certificateLogin = !mode.equals("password");
    adminCertificateUsername = config.getProperty("WEB_ADMIN_CLIENT_USERNAME", "admin");
    adminCertificateFingerprint =
        certificateLogin
            ? certificateFingerprint(config.getProperty("WEB_ADMIN_CLIENT_CERT_FILE"))
            : new byte[0];
    // Unknown usernames still incur one password verification.
    dummyHash = passwords.encode(UUID.randomUUID().toString());
  }

  public Reply<ApiResponse<Map<String, Object>>> login(
      Map<String, String> credentials, HttpServletRequest request, HttpServletResponse response) {
    if (!passwordLogin) {
      return invalid();
    }
    String username = credentials.get("username"), password = credentials.get("password");
    request.setAttribute(AuditFilter.ACTOR, username);
    response.setHeader("Cache-Control", "no-store");
    if (username == null
        || username.length() > 128
        || password == null
        || password.getBytes(StandardCharsets.UTF_8).length > 72) {
      return invalid();
    }
    throttle.reserve(username, request.getRemoteAddr());
    WebPrincipal user;
    try {
      user = users.loadUserByUsername(username);
    } catch (ApiException ex) {
      if (ex.status() != 401) {
        throw ex;
      }
      passwords.matches(password, dummyHash);
      return invalid();
    }
    if (!passwords.matches(password, user.getPassword()) || !user.isEnabled()) {
      return invalid();
    }
    user = accounts.upgradePasswordAfterLogin(user, password);
    sessions.login(request, response, user);
    throttle.success(username);
    accounts.recordLogin(user);
    return Reply.ok(ApiResponse.ok(userData(user)));
  }

  /** Authenticates the pinned bootstrap user from the certificate validated by the TLS connector. */
  public Reply<ApiResponse<Map<String, Object>>> certificate(
      HttpServletRequest request, HttpServletResponse response) {
    response.setHeader("Cache-Control", "no-store");
    Object attribute = request.getAttribute("jakarta.servlet.request.X509Certificate");
    if (!certificateLogin || !(attribute instanceof X509Certificate[] chain) || chain.length == 0) {
      return invalid();
    }
    byte[] presented;
    try {
      presented = MessageDigest.getInstance("SHA-256").digest(chain[0].getEncoded());
    } catch (Exception ex) {
      throw new IllegalStateException("Unable to inspect client certificate", ex);
    }
    if (!MessageDigest.isEqual(adminCertificateFingerprint, presented)) {
      return invalid();
    }
    WebPrincipal user = users.loadUserByUsername(adminCertificateUsername);
    if (!user.isEnabled()) {
      return invalid();
    }
    request.setAttribute(AuditFilter.ACTOR, user.getUsername());
    sessions.login(request, response, user);
    accounts.recordLogin(user);
    return Reply.ok(ApiResponse.ok(userData(user)));
  }

  /** Returns enabled login mechanisms so the UI can reflect operator-selected deployment mode. */
  public Map<String, Boolean> methods() {
    return Map.of("password", passwordLogin, "certificate", certificateLogin);
  }

  /** Loads and hashes the configured certificate so subject-name spoofing cannot select a user. */
  private static byte[] certificateFingerprint(String file) {
    if (file == null || file.isBlank()) {
      throw new IllegalArgumentException("WEB_ADMIN_CLIENT_CERT_FILE is required");
    }
    try (var input = Files.newInputStream(Path.of(file))) {
      X509Certificate certificate =
          (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
      return MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
    } catch (Exception ex) {
      throw new IllegalArgumentException("Unable to load WEB_ADMIN_CLIENT_CERT_FILE", ex);
    }
  }

  private static Reply<ApiResponse<Map<String, Object>>> invalid() {
    return Reply.status(401).body(ApiResponse.error("Invalid credentials"));
  }

  // Password also names the hashing service used by this controller.
  public ApiResponse<Void> password(
      IdentityRequests.Password body, HttpServletRequest req, HttpServletResponse resp) {
    resp.setHeader("Cache-Control", "no-store");
    throttle.reserve("password:" + AccountService.principal().getUsername(), req.getRemoteAddr());
    accounts.changePassword(body.currentPassword, body.newPassword);
    sessions.logout(req, resp);
    return ApiResponse.ok();
  }

  public ApiResponse<Void> reauth(Reauth body, HttpServletRequest req, HttpServletResponse resp) {
    resp.setHeader("Cache-Control", "no-store");
    String key = "reauth:" + AccountService.principal().getUsername();
    throttle.reserve(key, req.getRemoteAddr());
    accounts.reauthenticate(body.password);
    throttle.success(key);
    sessions.confirm(req);
    return ApiResponse.ok();
  }

  public ApiResponse<Map<String, Object>> currentUser() {
    var user = AccountService.principal();
    var data = userData(user);
    data.put("displayName", accounts.currentDisplayName());
    return ApiResponse.ok(data);
  }

  public ApiResponse<Map<String, Object>> profile(Update body, HttpServletResponse resp) {
    resp.setHeader("Cache-Control", "no-store");
    accounts.updateOwnProfile(body.displayName);
    return ApiResponse.ok(Collections.singletonMap("displayName", body.displayName));
  }

  public ApiResponse<Void> logout(HttpServletRequest req, HttpServletResponse resp) {
    sessions.logout(req, resp);
    return ApiResponse.ok();
  }

  private static Map<String, Object> userData(WebPrincipal user) {
    var data = new LinkedHashMap<String, Object>();
    data.put("username", user.getUsername());
    data.put("id", user.id());
    data.put("displayName", user.displayName());
    data.put("passwordChangeRequired", user.passwordChangeRequired());
    data.put("bindings", user.bindings());
    data.put(
        "roles",
        user.getAuthorities().stream()
            .map(Authority::getAuthority)
            .filter(a -> a.startsWith("ROLE_"))
            .map(a -> a.substring(5))
            .distinct()
            .sorted()
            .toList());
    data.put(
        "permissions",
        user.getAuthorities().stream()
            .map(Authority::getAuthority)
            .filter(a -> a.startsWith("PERM_"))
            .map(a -> a.substring(5))
            .distinct()
            .sorted()
            .toList());
    var rolePermissions = new LinkedHashMap<String, Set<String>>();
    for (var binding : user.bindings()) {
      rolePermissions.put(
          binding.role(),
          binding.definition().active() ? binding.definition().permissions() : Set.of());
    }
    data.put("rolePermissions", rolePermissions);
    return data;
  }
}
