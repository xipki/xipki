// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.store;

/**
 * Simple IssuerEntry containing only the id and RevocationTime.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class SimpleIssuerEntry {

  private final int id;

  private final Long revocationTimeMs;

  SimpleIssuerEntry(int id, Long revocationTimeMs) {
    this.id = id;
    this.revocationTimeMs = revocationTimeMs;
  }

  public boolean match(IssuerEntry issuer) {
    if (id != issuer.getId()) {
      return false;
    }

    if (revocationTimeMs == null) {
      return issuer.getRevocationInfo() == null;
    }

    return issuer.getRevocationInfo() != null
        && revocationTimeMs == issuer.getRevocationInfo().getRevocationTime().getTime();
  }

} // class SimpleIssuerEntry

