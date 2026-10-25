// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ocsp;

/**
 * OCSP Cert Status enumeration.
 *
 * @author Lijun Liao (xipki)
 */
public enum QaOcspCertStatus {

  issuerUnknown,
  unknown,
  good,
  rev_noreason,
  unspecified,
  keyCompromise,
  cACompromise,
  affiliationChanged,
  superseded,
  cessationOfOperation,
  certificateHold,
  removeFromCRL,
  privilegeWithdrawn,
  aACompromise;

  public static QaOcspCertStatus forName(String name) {
    for (QaOcspCertStatus entry : values()) {
      if (entry.name().equalsIgnoreCase(name)) {
        return entry;
      }
    }

    throw new IllegalArgumentException("invalid OcspCertStatus " + name);
  }

}
