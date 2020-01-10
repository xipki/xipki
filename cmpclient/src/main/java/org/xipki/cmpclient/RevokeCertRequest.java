/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.util.Args;

/**
 * CMP request to revoke certificates.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RevokeCertRequest {

  public static class Entry extends UnrevokeOrRemoveCertRequest.Entry {

    private int reason;

    private Date invalidityDate;

    private byte[] authorityKeyIdentifier;

    public Entry(String id, X509Certificate cert, int reason, Date invalidityDate) {
      this(id, X500Name.getInstance(cert.getIssuerX500Principal().getEncoded()),
          cert.getSerialNumber(), reason, invalidityDate);
    }

    public Entry(String id, X500Name issuer, BigInteger serialNumber, int reason,
        Date invalidityDate) {
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

    public Date getInvalidityDate() {
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
