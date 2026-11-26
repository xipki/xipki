// License Apache License 2.0

package org.xipki.mgmt.web.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.util.*;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.CaManager;
import org.xipki.mgmt.web.core.ApiException;
import org.xipki.mgmt.web.core.Config;

/**
 * Owns the narrow authorization that lets the deployment-generated Gateway RA identity use a
 * Quick Start CA. Existing user-managed requestors are never overwritten or broadened.
 */
final class GatewayRequestorProvisioner {
  static final String REQUESTOR = "gateway-ra";
  private static final int PERMISSIONS =
      PermissionConstants.ENROLL_CERT
          | PermissionConstants.REVOKE_CERT
          | PermissionConstants.UNSUSPEND_CERT;
  private static final Set<String> PROFILES =
      Set.of(QuickStartService.SERVER_PROFILE, QuickStartService.CLIENT_PROFILE);

  enum State {
    DISABLED,
    MISSING,
    READY,
    CONFLICT
  }

  private final String certificate;

  private GatewayRequestorProvisioner(String certificate) {
    this.certificate = certificate;
  }

  /** Returns a no-op adapter for tests or deployments without a generated Gateway identity. */
  static GatewayRequestorProvisioner disabled() {
    return new GatewayRequestorProvisioner(null);
  }

  /** Loads and canonicalizes the public Gateway RA certificate configured for Console startup. */
  static GatewayRequestorProvisioner from(Config config) {
    String filename = config.getProperty("XIPKI_GATEWAY_RA_CERT_FILE", "").trim();
    if (filename.isEmpty()) {
      return disabled();
    }
    try {
      byte[] source = Files.readAllBytes(Path.of(filename));
      byte[] der = CertificateFactory.getInstance("X.509")
          .generateCertificate(new java.io.ByteArrayInputStream(source))
          .getEncoded();
      return fromDer(der);
    } catch (Exception ex) {
      throw new IllegalStateException("Unable to load Gateway RA certificate", ex);
    }
  }

  /** Creates a configured instance from canonical DER; package visibility keeps tests focused. */
  static GatewayRequestorProvisioner fromDer(byte[] certificate) {
    if (certificate == null || certificate.length == 0) {
      throw new IllegalArgumentException("Gateway RA certificate is empty");
    }
    return new GatewayRequestorProvisioner(Base64.getEncoder().encodeToString(certificate));
  }

  /** Reports whether the exact deployment-owned requestor and least-privilege binding exist. */
  State state(CaManager manager, String caName) throws CaMgmtException {
    if (certificate == null) {
      return State.DISABLED;
    }
    String existingName = find(manager.getRequestorNames(), REQUESTOR);
    if (existingName == null) {
      return State.MISSING;
    }
    RequestorEntry requestor = manager.getRequestor(existingName);
    if (!matches(requestor)) {
      return State.CONFLICT;
    }
    if (caName == null) {
      return State.MISSING;
    }
    for (CaHasRequestorEntry association : manager.getRequestorsForCa(caName)) {
      if (association.getRequestorIdent().getName().equalsIgnoreCase(existingName)) {
        return exact(association) ? State.READY : State.CONFLICT;
      }
    }
    return State.MISSING;
  }

  /**
   * Creates only missing owned state. A same-name certificate or authorization mismatch is a
   * conflict because silently replacing or broadening an operator-managed identity is unsafe.
   */
  void ensure(CaManager manager, String caName) throws CaMgmtException {
    if (certificate == null) {
      return;
    }
    State before = state(manager, caName);
    if (before == State.READY) {
      return;
    }
    if (before == State.CONFLICT) {
      throw new ApiException(409, "Gateway RA requestor conflicts with Quick Start");
    }
    String existingName = find(manager.getRequestorNames(), REQUESTOR);
    if (existingName == null) {
      manager.addRequestor(
          new RequestorEntry(new NameId(null, REQUESTOR), "cert", certificate));
      existingName = REQUESTOR;
    }
    String requestorName = existingName;
    boolean associated = manager.getRequestorsForCa(caName).stream()
        .anyMatch(e -> e.getRequestorIdent().getName().equalsIgnoreCase(requestorName));
    if (!associated) {
      manager.addRequestorToCa(
          new CaHasRequestorEntry(
              new NameId(null, requestorName), new Permissions(PERMISSIONS), PROFILES),
          caName);
    }
  }

  /** Matches a certificate requestor by canonical DER instead of formatting or Base64 wrapping. */
  private boolean matches(RequestorEntry requestor) {
    if (requestor == null || !"cert".equalsIgnoreCase(requestor.getType())) {
      return false;
    }
    try {
      return Arrays.equals(
          Base64.getDecoder().decode(certificate),
          Base64.getMimeDecoder().decode(requestor.getConf()));
    } catch (IllegalArgumentException ex) {
      return false;
    }
  }

  /** Requires the exact permissions and profiles promised by the Quick Start security contract. */
  private boolean exact(CaHasRequestorEntry association) {
    return association.getPermissions() != null
        && association.getPermissions().getValue() == PERMISSIONS
        && association.getProfiles() != null
        && new TreeSet<>(association.getProfiles()).equals(new TreeSet<>(PROFILES));
  }

  /** Finds the stored spelling of one case-insensitive XiPKI resource name. */
  private String find(Set<String> names, String expected) {
    return names.stream().filter(n -> n.equalsIgnoreCase(expected)).findFirst().orElse(null);
  }
}
