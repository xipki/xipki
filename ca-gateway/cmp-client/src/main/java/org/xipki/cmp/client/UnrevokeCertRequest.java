// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.util.Args;

import java.math.BigInteger;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * CMP request to unrevoke or remove certificates.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class UnrevokeCertRequest {

  public static class Entry extends IdentifiedObject {

    private final X500Name issuer;

    private final BigInteger serialNumber;

    private byte[] authorityKeyIdentifier;

    public Entry(String id, X500Name issuer, BigInteger serialNumber) {
      super(id);
      this.serialNumber = Args.notNull(serialNumber, "serialNumber");
      this.issuer = Args.notNull(issuer, "issuer");
    }

    public X500Name getIssuer() {
      return issuer;
    }

    public BigInteger getSerialNumber() {
      return serialNumber;
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
