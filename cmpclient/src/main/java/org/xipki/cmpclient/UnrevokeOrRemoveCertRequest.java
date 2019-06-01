/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.cmpclient;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.util.Args;

/**
 * CMP request to unrevoke or remove certificates.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class UnrevokeOrRemoveCertRequest {

  public static class Entry extends IdentifiedObject {

    private final X500Name issuer;

    private final BigInteger serialNumber;

    private byte[] authorityKeyIdentifier;

    public Entry(String id, X509Certificate cert) {
      this(id, X500Name.getInstance(cert.getIssuerX500Principal().getEncoded()),
          cert.getSerialNumber());
    }

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

  }

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
