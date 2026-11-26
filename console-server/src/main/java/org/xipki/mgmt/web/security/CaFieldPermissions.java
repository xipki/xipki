// License Apache License 2.0

package org.xipki.mgmt.web.security;

import java.util.*;
import org.xipki.mgmt.web.ca.CaDomain.CaMgmtException;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.CaConfigurationRequest;

/**
 * Explicit submitted-field policy shared by CA PUT aliases and audit classification.
 *
 * @author palos
 */
public final class CaFieldPermissions {
  public static Set<String> actions(CaConfigurationRequest r) {
    if (r == null) {
      throw new IllegalArgumentException("Configuration required");
    }
    var actions = new TreeSet<String>();
    if (r.status != null) {
      actions.add("CA_STATUS_UPDATE");
    }
    if (Boolean.TRUE.equals(r.acceptUnknownRevocation)) {
      actions.add("CA_STATUS_UPDATE");
    }
    if (r.key != null
        || r.signerType != null
        || r.signerConf != null
        || Boolean.TRUE.equals(r.replaceSigner)) {
      actions.add("CA_KEY_REPLACE");
    }
    if (r.encodedCert != null
        || r.encodedCertchain != null
        || Boolean.TRUE.equals(r.replaceCertificates)) {
      actions.add("CA_CERT_REPLACE");
    }
    if (r.crlSignerName != null || r.keypairGenNames != null || r.saveKeypair != null) {
      actions.add("CA_CRYPTO_CONFIG_UPDATE");
    }
    if (r.permissions != null) {
      actions.add("CA_ENGINE_PERMISSIONS_UPDATE");
    }
    if (r.maxValidity != null
        || r.validityMode != null
        || r.crlControl != null
        || r.ctlogControl != null
        || r.revokeSuspendedControl != null
        || r.saveCert != null
        || r.keepExpiredCertDays != null
        || r.expirationPeriod != null
        || r.extraControl != null
        || r.caUris != null
        || r.numCrls != null
        || r.serialNoLen != null) {
      actions.add("CA_CONFIG_UPDATE");
    }
    return Set.copyOf(actions);
  }

  public static String authorize(AccessControl access, String name, CaConfigurationRequest request)
      throws CaMgmtException {
    var actions = actions(request);
    if (actions.isEmpty()) {
      throw new IllegalArgumentException("No configuration changes submitted");
    }
    // All authorization precedes material validation/preparation and any remote write.
    var identity = access.identity(name);
    for (String action : actions) {
      if (!access.allows(action, identity, null)) {
        throw new AccessDeniedException("Permission denied");
      }
      if (PermissionCatalog.get(action).recentAuthRequired()) {
        RecentAuthentication.require();
      }
    }
    if (Boolean.TRUE.equals(request.replaceSigner) && request.key == null) {
      throw new IllegalArgumentException("Signer replacement requires structured key material");
    }
    if (Boolean.TRUE.equals(request.replaceCertificates)
        && request.encodedCert == null
        && request.encodedCertchain == null) {
      throw new IllegalArgumentException("Certificate replacement requires certificate material");
    }
    if (Boolean.TRUE.equals(request.acceptUnknownRevocation)) {
      RecentAuthentication.require();
    }
    return identity.name();
  }

  private CaFieldPermissions() {}
}
