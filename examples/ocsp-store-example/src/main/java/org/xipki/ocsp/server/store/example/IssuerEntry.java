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

package org.xipki.ocsp.server.store.example;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.ocsp.api.RequestIssuer;
import org.xipki.security.HashAlgo;
import org.xipki.util.Args;
import org.xipki.util.CompareUtil;

/**
 * Issuer entry.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class IssuerEntry {

  private final Map<HashAlgo, byte[]> issuerHashMap;

  private final X509Certificate cert;

  public IssuerEntry(X509Certificate cert) throws IOException, CertificateEncodingException {
    this.cert = Args.notNull(cert, "cert");
    this.issuerHashMap = getIssuerHashAndKeys(cert.getEncoded());
  }

  private static Map<HashAlgo, byte[]> getIssuerHashAndKeys(byte[] encodedCert)
      throws IOException {
    Certificate bcCert = Certificate.getInstance(encodedCert);
    byte[] encodedName = bcCert.getSubject().getEncoded("DER");
    byte[] encodedKey = bcCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();

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
    return hashes;
  }

  public boolean matchHash(RequestIssuer reqIssuer) {
    byte[] issuerHash = issuerHashMap.get(reqIssuer.hashAlgorithm());
    if (issuerHash == null) {
      return false;
    }

    return CompareUtil.areEqual(issuerHash, 0, reqIssuer.getData(),
        reqIssuer.getNameHashFrom(), issuerHash.length);
  }

  public X509Certificate getCert() {
    return cert;
  }

}
