// License Apache License 2.0

package org.xipki.mgmt.web.audit;

import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.stream.Collectors;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.ApiResponse;
import org.xipki.mgmt.web.security.ManagementApiPolicy;

/**
 * Middleware helper: durable attempts precede mutations; completion storage failures propagate.
 *
 * @author palos
 */
public final class AuditFilter {
  public static final String ACTOR = AuditFilter.class.getName() + ".actor",
      BUSINESS_FAILURE = AuditFilter.class.getName() + ".businessFailure";
  private static final String INITIAL_ACTOR = AuditFilter.class.getName() + ".initialActor";
  private static final Set<String> GET_DOWNLOAD_ROUTES =
      Set.of(
          "/api/audit/export",
          "/api/system/export",
          "/api/ca/{name}/certificates",
          "/api/ca-enrollments/{id}/csr",
          "/api/cert/{ca}/{serial}/download",
          "/api/crl/{ca}/current",
          "/api/crl/{ca}/{number}");
  private final AuditService audit;

  public AuditFilter(AuditService audit) {
    this.audit = audit;
  }

  private static boolean audited(HttpServletRequest req) {
    String path = req.getRequestURI();
    if (!path.startsWith("/api/") || path.equals("/api/auth/csrf")) {
      return false;
    }
    String method = req.getMethod();
    if (method.equals("GET")) {
      var rule = ManagementApiPolicy.match(method, path);
      return rule != null && GET_DOWNLOAD_ROUTES.contains(rule.path());
    }
    return !Set.of("HEAD", "FETCH", "OPTIONS").contains(method);
  }

  public long begin(HttpServletRequest request) {
    long start = System.nanoTime();
    request.setAttribute(INITIAL_ACTOR, actor());
    if (audited(request) && !Set.of("GET", "HEAD", "OPTIONS").contains(request.getMethod())) {
      record(event(request, actor(), "ATTEMPT", null, start));
    }
    return start;
  }

  public void finish(
      HttpServletRequest request, int status, Object body, Throwable error, long start) {
    if (!audited(request)) {
      return;
    }
    String who = actor();
    if (who == null) {
      who = (String) request.getAttribute(INITIAL_ACTOR);
    }
    if (who == null) {
      who = (String) request.getAttribute(ACTOR);
    }
    String failure =
        error != null
            ? "REQUEST_EXCEPTION"
            : status >= 400 ? "HTTP_" + status : (String) request.getAttribute(BUSINESS_FAILURE);
    if (body instanceof ApiResponse<?> api && !api.isSuccess()) {
      failure = "BUSINESS_FAILURE";
    }
    record(event(request, who, failure == null ? "SUCCESS" : "FAILURE", failure, start));
  }

  private void record(AuditEvent event) {
    try {
      audit.record(event);
    } catch (RuntimeException ex) {
      throw new ApiException(
          503, "Audit storage temporarily unavailable; verify operation result before retry");
    }
  }

  public static String actor() {
    var p = RequestContext.principal();
    return p == null ? null : p.getUsername();
  }

  public static AuditEvent event(
      HttpServletRequest request, String actor, String result, String failure, long start) {
    var rule = ManagementApiPolicy.match(request.getMethod(), request.getRequestURI());
    String action =
        request.getMethod() + " " + (rule == null ? request.getRequestURI() : rule.path());
    String[] parts = request.getRequestURI().split("/");
    String type = parts.length > 2 ? parts[2] : "api";
    var identifiers = new TreeMap<String, String>();
    // Do not parse multipart/form data here: authentication and size gates run before it.
    if (!type.equals("auth") && parts.length > 3) {
      identifiers.put("target", String.join("/", Arrays.copyOfRange(parts, 3, parts.length)));
    }
    identifiers.putAll(AuditTargetCapture.identifiers(request));
    if (Set.of("profile", "publisher", "requestor").contains(type)
        && request.getRequestURI().matches("/api/[^/]+/(?:[^/]+/)?ca/[^/]+(?:/associations)?")) {
      type = "ca-" + type + "-association";
    } else if (type.equals("users")) {
      type = "user";
    } else if (type.equals("roles")) {
      type = "role";
    }
    String id =
        identifiers.entrySet().stream()
            .map(e -> e.getKey() + "=" + e.getValue())
            .collect(Collectors.joining(","));
    return new AuditEvent(
        actor,
        null,
        request.getRemoteAddr(),
        (String) request.getAttribute(RequestIdFilter.ATTRIBUTE),
        request.getMethod(),
        request.getRequestURI(),
        action,
        result,
        failure,
        (System.nanoTime() - start) / 1_000_000,
        type,
        id,
        ManagementApiPolicy.permissionCodes(request));
  }
}
