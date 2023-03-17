// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ocsp;

/**
 * OCSP Certstatus enum.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public enum OcspCertStatus {

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

  public static OcspCertStatus forName(String name) {
    for (OcspCertStatus entry : values()) {
      if (entry.name().equalsIgnoreCase(name)) {
        return entry;
      }
    }

    throw new IllegalArgumentException("invalid OcspCertStatus " + name);
  }

}
