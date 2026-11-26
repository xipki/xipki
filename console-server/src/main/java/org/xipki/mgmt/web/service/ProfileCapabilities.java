// License Apache License 2.0

package org.xipki.mgmt.web.service;

import java.util.Set;
import org.xipki.mgmt.web.core.*;

/**
 * Public, non-secret capabilities needed before a profile can issue a CA certificate.
 *
 * @author palos
 */
public record ProfileCapabilities(
    CertLevel level, Integer pathLenConstraint, Set<String> keyAlgorithms, String diagnostic) {
  public enum CertLevel {
    ROOT_CA,
    SUB_CA,
    END_ENTITY,
    CROSS,
    UNKNOWN
  }

  public boolean supportsSubCa() {
    return level == CertLevel.SUB_CA;
  }
}
