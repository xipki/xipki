// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.util.codec.Args;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * CMP request to revoke certificates.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class RevokeCertRequest {

  public static class Entry extends UnsuspendCertRequest.Entry {

    private final int reason;

    private final Instant invalidityDate;

    private byte[] authorityKeyIdentifier;

    public Entry(String id, X500Name issuer, BigInteger serialNumber,
                 int reason, Instant invalidityDate) {
      super(id, issuer, serialNumber);

      if (!(reason >= 0 && reason <= 10 && reason != 7)) {
        throw new IllegalArgumentException("invalid reason: " + reason);
      }

      this.reason = reason;
      this.invalidityDate = invalidityDate;
    }

    public int getReason() {
      return reason;
    }

    public Instant getInvalidityDate() {
      return invalidityDate;
    }

    public byte[] getAuthorityKeyIdentifier() {
      return authorityKeyIdentifier;
    }

    public void setAuthorityKeyIdentifier(byte[] authorityKeyIdentifier) {
      this.authorityKeyIdentifier = authorityKeyIdentifier;
    }

  } // class Entry

  private final List<Entry> requestEntries = new LinkedList<>();

  public boolean addRequestEntry(Entry requestEntry) {
    Args.notNull(requestEntry, "requestEntry");
    for (Entry re : requestEntries) {
      if (re.getId().equals(requestEntry.getId())) {
        return false;
      }
    }

    requestEntries.add(requestEntry);
    return true;
  }

  public List<Entry> getRequestEntries() {
    return Collections.unmodifiableList(requestEntries);
  }

}
