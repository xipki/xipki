// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.store;

import java.time.Instant;

/**
 * Simple IssuerEntry containing only the id and RevocationTime.
 *
 * @author Lijun Liao (xipki)
 */

class SimpleIssuerEntry {

  private final int id;

  private final Instant revocationTime;

  SimpleIssuerEntry(int id, Instant revocationTime) {
    this.id = id;
    this.revocationTime = revocationTime;
  }

  public boolean match(IssuerEntry issuer) {
    if (id != issuer.id()) {
      return false;
    }

    if (revocationTime == null) {
      return issuer.revocationInfo() == null;
    }

    return issuer.revocationInfo() != null
        && revocationTime == Instant.ofEpochSecond(
            issuer.revocationInfo().revocationTime().getEpochSecond());
  }

} // class SimpleIssuerEntry

