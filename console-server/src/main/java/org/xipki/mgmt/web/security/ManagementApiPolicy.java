// License Apache License 2.0

package org.xipki.mgmt.web.security;

import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import org.xipki.mgmt.web.core.*;

/**
 * Explicit entry-point allowlist; object/profile/field checks remain at the business boundary.
 *
 * @author palos
 */
public final class ManagementApiPolicy {
  public record Rule(
      String method, String path, List<String> anyPermission, boolean publicEntry, boolean self) {}

  private static final List<Rule> RULES;

  static {
    var r = new ArrayList<Rule>();
    r.add(new Rule("POST", "/api/auth/login", List.of(), true, false));
    r.add(new Rule("POST", "/api/auth/certificate", List.of(), true, false));
    r.add(new Rule("GET", "/api/auth/methods", List.of(), true, false));
    r.add(new Rule("GET", "/api/auth/csrf", List.of(), true, false));
    r.add(new Rule("GET", "/health/live", List.of(), true, false));
    r.add(new Rule("GET", "/health/ready", List.of(), true, false));
    for (String path : List.of("password", "reauth", "logout")) {
      r.add(new Rule("POST", "/api/auth/" + path, List.of(), false, true));
    }
    r.add(new Rule("GET", "/api/auth/me", List.of(), false, true));
    r.add(new Rule("PUT", "/api/auth/profile", List.of(), false, true));
    for (String resource : List.of("signer", "requestor", "publisher", "profile", "keypairgen")) {
      String prefix = resource.toUpperCase(Locale.ROOT);
      rule(r, "GET", "/api/" + resource, prefix + "_READ");
      rule(r, "GET", "/api/" + resource + "/{name}", prefix + "_READ");
      rule(r, "POST", "/api/" + resource, prefix + "_CREATE");
      rule(r, "PUT", "/api/" + resource + "/{name}", prefix + "_UPDATE");
      rule(r, "DELETE", "/api/" + resource + "/{name}", prefix + "_DELETE");
    }
    String declarations =
        """
        GET /api/audit AUDIT_READ
        GET /api/audit/export AUDIT_EXPORT
        GET /api/audit/context AUDIT_CONTEXT_READ
        GET /api/dashboard CA_READ
        GET /api/quick-start CA_CREATE_ROOT
        POST /api/quick-start CA_CREATE_ROOT
        GET /api/users USER_READ
        GET /api/users/{id} USER_READ
        POST /api/users USER_CREATE
        PUT /api/users/{id} USER_UPDATE
        POST /api/users/{id}/status USER_STATUS_UPDATE
        POST /api/users/{id}/reset-password USER_PASSWORD_RESET
        POST /api/users/{id}/sessions/revoke USER_SESSION_REVOKE
        GET /api/access-options USER_ROLE_ASSIGN
        PUT /api/users/{id}/role-bindings USER_ROLE_ASSIGN
        GET /api/roles ROLE_READ
        GET /api/permissions ROLE_READ
        POST /api/roles ROLE_MANAGE
        PUT /api/roles/{name} ROLE_MANAGE
        DELETE /api/roles/{name} ROLE_MANAGE
        GET /api/dbschema DBSCHEMA_READ
        POST /api/dbschema DBSCHEMA_CREATE
        PUT /api/dbschema/{name} DBSCHEMA_UPDATE
        DELETE /api/dbschema/{name} DBSCHEMA_DELETE
        GET /api/system/status SYSTEM_READ
        POST /api/system/restart SYSTEM_RESTART
        POST /api/system/unlock SYSTEM_UNLOCK
        POST /api/system/notify-change SYSTEM_NOTIFY_CHANGE
        GET /api/system/token-info TOKEN_READ
        GET /api/system/export CONFIG_EXPORT
        POST /api/system/import CONFIG_IMPORT
        POST /api/system/republish CERT_REPUBLISH
        GET /api/system/supported-types SIGNER_READ,SIGNER_CREATE,SIGNER_UPDATE,\
        PROFILE_READ,PROFILE_CREATE,PROFILE_UPDATE,PUBLISHER_READ,PUBLISHER_CREATE,\
        PUBLISHER_UPDATE
        GET /api/ca CA_READ
        GET /api/ca-enrollments CA_IMPORT,CA_ISSUE_SUBCA
        GET /api/ca-enrollments/options CA_IMPORT,CA_ISSUE_SUBCA
        POST /api/ca-enrollments CA_IMPORT,CA_ISSUE_SUBCA
        GET /api/ca-enrollments/{id} CA_IMPORT,CA_ISSUE_SUBCA
        GET /api/ca-enrollments/{id}/csr CA_IMPORT,CA_ISSUE_SUBCA
        POST /api/ca-enrollments/{id}/issue CA_IMPORT,CA_ISSUE_SUBCA
        POST /api/ca-enrollments/{id}/certificate CA_IMPORT,CA_ISSUE_SUBCA
        POST /api/ca-enrollments/{id}/register CA_IMPORT
        POST /api/ca-enrollments/{id}/reconcile CA_IMPORT,CA_ISSUE_SUBCA
        POST /api/ca-enrollments/{id}/cancel CA_IMPORT,CA_ISSUE_SUBCA
        GET /api/ca/{name} CA_READ
        POST /api/ca CA_IMPORT
        POST /api/ca/preflight CA_IMPORT
        POST /api/ca/root CA_CREATE_ROOT
        GET /api/ca/{name}/config CA_CONFIG_READ
        PUT /api/ca/{name}/config CA_CONFIG_UPDATE,CA_STATUS_UPDATE,CA_KEY_REPLACE,\
        CA_CERT_REPLACE,CA_CRYPTO_CONFIG_UPDATE,CA_ENGINE_PERMISSIONS_UPDATE
        GET /api/ca/{name}/certificates CA_READ
        DELETE /api/ca/{name} CA_DELETE
        GET /api/ca/{name}/delete-impact CA_DELETE
        POST /api/ca/{name}/revoke CA_REVOKE
        POST /api/ca/{name}/unrevoke CA_UNREVOKE
        POST /api/ca/{name}/restart CA_RESTART
        GET /api/ca/aliases CA_READ
        POST /api/ca/aliases CA_ALIAS_CREATE
        DELETE /api/ca/aliases/{alias} CA_ALIAS_DELETE
        GET /api/ca-options CA_CREATE_ROOT,CA_IMPORT,CA_CONFIG_READ,CA_CRYPTO_CONFIG_UPDATE
        GET /api/ca/{name}/association-options CA_PROFILE_BIND,CA_PUBLISHER_BIND,\
        CA_REQUESTOR_BIND,CA_REQUESTOR_ACCESS_UPDATE
        GET /api/ca/{name}/crypto-options CA_CRYPTO_CONFIG_UPDATE
        GET /api/profile/ca/{ca} CA_READ
        GET /api/profile/ca/{ca}/associations CA_PROFILE_READ
        POST /api/profile/{name}/ca/{ca} CA_PROFILE_BIND
        DELETE /api/profile/{name}/ca/{ca} CA_PROFILE_UNBIND
        GET /api/publisher/ca/{ca} CA_PUBLISHER_READ
        POST /api/publisher/{name}/ca/{ca} CA_PUBLISHER_BIND
        DELETE /api/publisher/{name}/ca/{ca} CA_PUBLISHER_UNBIND
        GET /api/requestor/ca/{ca} CA_REQUESTOR_READ
        POST /api/requestor/{name}/ca/{ca} CA_REQUESTOR_BIND
        PUT /api/requestor/{name}/ca/{ca} CA_REQUESTOR_ACCESS_UPDATE
        DELETE /api/requestor/{name}/ca/{ca} CA_REQUESTOR_UNBIND
        GET /api/cert CERT_READ
        GET /api/cert/{ca}/{serial} CERT_READ
        GET /api/cert/{ca}/{serial}/download CERT_READ
        POST /api/cert/enroll CERT_ISSUE
        POST /api/cert/enroll-cross CERT_CROSS
        POST /api/cert/enroll-key CERT_KEYGEN
        POST /api/cert/enroll-key/download CERT_KEYGEN
        POST /api/cert/{ca}/{serial}/revoke CERT_REVOKE,CERT_SUSPEND
        POST /api/cert/{ca}/{serial}/unsuspend CERT_UNSUSPEND
        DELETE /api/cert/{ca}/{serial} CERT_DELETE
        GET /api/crl/{ca}/current CRL_READ
        GET /api/crl/{ca}/{number} CRL_READ
        POST /api/crl/{ca}/generate CRL_GENERATE
        """;
    for (String line : declarations.strip().split("\\R")) {
      String[] parts = line.strip().split(" ");
      rule(r, parts[0], parts[1], parts[2]);
    }
    RULES = List.copyOf(r);
  }

  private static void rule(List<Rule> rules, String method, String path, String permissions) {
    var codes = List.of(permissions.split(","));
    codes.forEach(PermissionCatalog::get);
    rules.add(new Rule(method, path, codes, false, false));
  }

  public static List<Rule> rules() {
    return RULES;
  }

  public static Rule match(String method, String path) {
    // Prefer the most specific route: /ca/aliases must not inherit /ca/{name} by declaration order.
    return RULES.stream()
        .filter(r -> r.method().equals(method) && matches(r.path(), path))
        .min(Comparator.comparingInt(r -> (int) r.path().chars().filter(c -> c == '{').count()))
        .orElse(null);
  }

  public static boolean authorized(HttpServletRequest request, WebPrincipal principal) {
    var rule = match(request.getMethod(), request.getRequestURI());
    if (rule == null) {
      return false;
    }
    // The original version filter restricted every authenticated forced-change account,
    // including super administrators and already-authenticated calls to public API routes.
    if (principal != null
        && principal.passwordChangeRequired()
        && request.getRequestURI().startsWith("/api/")
        && !Set.of("/api/auth/me", "/api/auth/csrf", "/api/auth/password", "/api/auth/logout")
            .contains(request.getRequestURI())) {
      return false;
    }
    if (rule.publicEntry()) {
      return true;
    }
    if (principal == null || !principal.isEnabled()) {
      return false;
    }
    if (rule.self()) {
      return true;
    }
    for (String code : rule.anyPermission()) {
      boolean grant =
          principal.getAuthorities().stream()
              .anyMatch(a -> a.getAuthority().equals("PERM_" + code));
      if (grant && PermissionCatalog.get(code).scope().equals("PLATFORM")) {
        grant =
            principal.isSuperAdmin()
                || principal.bindings().stream()
                    .anyMatch(
                        b ->
                            b.scope().equals("PLATFORM")
                                && b.definition().active()
                                && b.definition().permissions().contains(code));
      }
      if (grant) {
        // Mixed/field-sensitive routes authorize each actual branch at the business boundary.
        if (rule.anyPermission().size() == 1
            && PermissionCatalog.get(code).recentAuthRequired()
            && (!request.getMethod().equals("GET") || code.equals("CONFIG_EXPORT"))) {
          RecentAuthentication.require();
        }
        return true;
      }
    }
    return false;
  }

  public static String permissionCodes(HttpServletRequest request) {
    Object captured = request.getAttribute("web.permissionCodes");
    if (captured instanceof Collection<?> values) {
      return String.join(",", values.stream().map(Object::toString).sorted().toList());
    }
    var rule = match(request.getMethod(), request.getRequestURI());
    if (rule == null || rule.anyPermission().size() != 1) {
      return "";
    }
    String code = rule.anyPermission().get(0);
    return code.equals("CA_REQUESTOR_BIND") ? "CA_REQUESTOR_ACCESS_UPDATE,CA_REQUESTOR_BIND" : code;
  }

  private static boolean matches(String pattern, String path) {
    String[] a = pattern.split("/", -1), b = path.split("/", -1);
    if (a.length != b.length) {
      return false;
    }
    for (int i = 0; i < a.length; i++) {
      if (a[i].startsWith("{") ? b[i].isEmpty() : !a[i].equals(b[i])) {
        return false;
      }
    }
    return true;
  }

  private ManagementApiPolicy() {}
}
