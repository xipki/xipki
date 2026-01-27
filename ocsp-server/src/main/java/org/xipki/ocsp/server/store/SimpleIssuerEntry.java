// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.store;

import java.time.Instant;

/**
 * Simple IssuerEntry containing only the id and RevocationTime.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class SimpleIssuerEntry {

  private final int id;

  private final Instant revocationTime;

  SimpleIssuerEntry(int id, Instant revocationTime) {
    this.id = id;
    this.revocationTime = revocationTime;
  }

  public boolean match(IssuerEntry issuer) {
    if (id != issuer.getId()) {
      return false;
    }

    if (revocationTime == null) {
      return issuer.getRevocationInfo() == null;
    }

    return issuer.getRevocationInfo() != null
        && revocationTime == Instant.ofEpochSecond(
            issuer.getRevocationInfo().getRevocationTime().getEpochSecond());
  }

} // class SimpleIssuerEntry

