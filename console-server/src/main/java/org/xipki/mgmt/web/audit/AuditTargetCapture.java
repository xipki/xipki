// License Apache License 2.0

package org.xipki.mgmt.web.audit;

import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import org.xipki.mgmt.web.ca.CaDomain.CrlReason;
import org.xipki.mgmt.web.core.ApiException;
import org.xipki.mgmt.web.dto.*;
import org.xipki.mgmt.web.dto.CaEnrollmentDtos.Prepare;
import org.xipki.mgmt.web.security.CaFieldPermissions;

/**
 * Explicit target allowlist; never captures CSRs, passwords, subjects or private keys.
 *
 * @author palos
 */
public final class AuditTargetCapture {
  private static final String ATTRIBUTE = AuditTargetCapture.class.getName();
  private final AuditService audit;

  public AuditTargetCapture(AuditService audit) {
    this.audit = audit;
  }

  @SuppressWarnings("unchecked")
  static Map<String, String> identifiers(HttpServletRequest req) {
    Object v = req.getAttribute(ATTRIBUTE);
    return v instanceof Map<?, ?> ? (Map<String, String>) v : Map.of();
  }

  public static void identify(HttpServletRequest req, String key, String value) {
    if (value == null) {
      return;
    }
    var values = new TreeMap<>(identifiers(req));
    values.put(key, value);
    req.setAttribute(ATTRIBUTE, values);
  }

  public void captureParameters(HttpServletRequest request) {
    if (!request.getRequestURI().startsWith("/api/cert")
        && !request.getRequestURI().startsWith("/api/crl")) {
      return;
    }
    for (String key : Set.of("ca", "profile")) {
      identify(request, key, request.getParameter(key));
    }
    if (!Set.of("GET", "HEAD", "OPTIONS").contains(request.getMethod())
        && !identifiers(request).isEmpty()) {
      recordIntent(request);
    }
  }

  public Object captureBody(HttpServletRequest req, Object body) {
    if (body instanceof Prepare e) {
      captureEnrollment(req, null, e.purpose, e.parentCa, e.profile, e.name);
      return body;
    }
    if (body instanceof CaConfigurationRequest config) {
      req.setAttribute("web.permissionCodes", CaFieldPermissions.actions(config));
    } else if (body instanceof NameTypeConfDto e) {
      identify(req, "name", e.getName());
    } else if (body instanceof CreateRootCaRequest e) {
      identify(req, "name", e.name);
      identify(req, "profile", e.profile);
    } else if (body instanceof QuickStartRequest e) {
      identify(req, "name", e.caName);
    } else if (body instanceof ImportCaRequest e) {
      identify(req, "name", e.name);
    } else if (body instanceof KeyCertDownloadRequest e) {
      identify(req, "ca", e.getCa());
      identify(req, "profile", e.getProfile());
    } else if (body instanceof RepublishRequest e) {
      identify(req, "caName", e.getCaName());
    } else if (body instanceof Map<?, ?> values) {
      if (req.getRequestURI().matches("/api/cert/[^/]+/[^/]+/revoke")) {
        try {
          var reason =
              CrlReason.forNameOrText(values.get("reason") instanceof String s ? s : "unspecified");
          req.setAttribute(
              "web.permissionCodes",
              Set.of(reason == CrlReason.CERTIFICATE_HOLD ? "CERT_SUSPEND" : "CERT_REVOKE"));
        } catch (IllegalArgumentException ignored) {
        }
      } else if (req.getRequestURI().equals("/api/ca/aliases")) {
        for (String field : List.of("alias", "caName")) {
          if (values.get(field) instanceof String value) {
            identify(req, field, value);
          }
        }
      } else if (req.getRequestURI().equals("/api/dbschema")
          && values.get("name") instanceof String name) {
        identify(req, "name", name);
      }
    }
    if (!Set.of("GET", "HEAD", "OPTIONS").contains(req.getMethod())
        && (!identifiers(req).isEmpty() || req.getAttribute("web.permissionCodes") != null)) {
      recordIntent(req);
    }
    return body;
  }

  public void captureEnrollment(
      HttpServletRequest req, String id, String purpose, String ca, String profile, String name) {
    identify(req, "operation", id);
    identify(req, "ca", ca);
    identify(req, "profile", profile);
    identify(req, "name", name);
    var permissions = new TreeSet<String>();
    if ("REGISTER_CA".equals(purpose)) {
      permissions.add("CA_IMPORT");
    }
    if (ca != null) {
      permissions.add("CA_ISSUE_SUBCA");
    }
    req.setAttribute("web.permissionCodes", permissions);
    recordIntent(req);
  }

  private void recordIntent(HttpServletRequest request) {
    try {
      audit.record(
          AuditFilter.event(request, AuditFilter.actor(), "ATTEMPT", null, System.nanoTime()));
    } catch (RuntimeException ex) {
      throw new ApiException(503, "Audit storage temporarily unavailable");
    }
  }
}
