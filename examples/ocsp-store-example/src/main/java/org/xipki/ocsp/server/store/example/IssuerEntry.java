// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.store.example;

import org.xipki.ocsp.api.RequestIssuer;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;
import org.xipki.util.CompareUtil;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Issuer entry.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class IssuerEntry {

  private final Map<HashAlgo, byte[]> issuerHashMap;

  private final X509Cert cert;

  public IssuerEntry(X509Cert cert) throws IOException {
    this.cert = Args.notNull(cert, "cert");
    byte[] encodedName = cert.getSubject().getEncoded("DER");
    byte[] encodedKey = cert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();

    Map<HashAlgo, byte[]> hashes = new HashMap<>();
    for (HashAlgo ha : HashAlgo.values()) {
      int hlen = ha.getLength();
      byte[] nameAndKeyHash = new byte[(2 + hlen) << 1];
      int offset = 0;
      nameAndKeyHash[offset++] = 0x04;
      nameAndKeyHash[offset++] = (byte) hlen;
      System.arraycopy(ha.hash(encodedName), 0, nameAndKeyHash, offset, hlen);
      offset += hlen;

      nameAndKeyHash[offset++] = 0x04;
      nameAndKeyHash[offset++] = (byte) hlen;
      System.arraycopy(ha.hash(encodedKey), 0, nameAndKeyHash, offset, hlen);

      hashes.put(ha, nameAndKeyHash);
    }
    this.issuerHashMap = hashes;
  } // method getIssuerHashAndKeys

  public boolean matchHash(RequestIssuer reqIssuer) {
    byte[] issuerHash = issuerHashMap.get(reqIssuer.hashAlgorithm());
    if (issuerHash == null) {
      return false;
    }

    return CompareUtil.areEqual(issuerHash, 0, reqIssuer.getData(), reqIssuer.getNameHashFrom(), issuerHash.length);
  }

  public X509Cert getCert() {
    return cert;
  }

}
