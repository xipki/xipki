// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.store.ejbca;

import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.ocsp.api.RequestIssuer;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.misc.CompareUtil;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * IssuerEntry for the EJBCA database.
 *
 * @author Lijun Liao (xipki)
 */

class EjbcaIssuerEntry {

  private final String id;

  private final Map<HashAlgo, byte[]> issuerHashMap;

  private final Instant notBefore;

  private final X509Cert cert;

  private CertRevocationInfo revocationInfo;

  public EjbcaIssuerEntry(X509Cert cert) throws CertificateEncodingException {
    this.cert = Args.notNull(cert, "cert");
    this.notBefore = cert.notBefore();
    byte[] encodedCert = cert.getEncoded();
    this.id = HashAlgo.SHA1.hexHash(encodedCert);
    this.issuerHashMap = getIssuerHashAndKeys(encodedCert);
  }

  private static Map<HashAlgo, byte[]> getIssuerHashAndKeys(byte[] encodedCert)
      throws CertificateEncodingException {
    byte[] encodedName;
    byte[] encodedKey;
    try {
      Certificate bcCert = Certificate.getInstance(encodedCert);
      encodedName = bcCert.getSubject().getEncoded("DER");
      encodedKey = bcCert.getSubjectPublicKeyInfo().getPublicKeyData()
                    .getBytes();
    } catch (IllegalArgumentException | IOException ex) {
      throw new CertificateEncodingException(ex.getMessage(), ex);
    }

    Map<HashAlgo, byte[]> hashes = new HashMap<>();
    for (HashAlgo ha : HashAlgo.values()) {
      int hlen = ha.length();
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
  } // method getIssuerHashAndKeys

  public String id() {
    return id;
  }

  public byte[] getEncodedHash(HashAlgo hashAlgo) {
    byte[] data = issuerHashMap.get(hashAlgo);
    return Arrays.copyOf(data, data.length);
  }

  public boolean matchHash(RequestIssuer reqIssuer) {
    byte[] issuerHash = issuerHashMap.get(reqIssuer.hashAlgorithm());
    return issuerHash != null &&
        CompareUtil.areEqual(issuerHash, 0, reqIssuer.data(),
            reqIssuer.nameHashFrom(), issuerHash.length);
  }

  public void setRevocationInfo(Instant revocationTime) {
    this.revocationInfo = new CertRevocationInfo(CrlReason.CA_COMPROMISE,
        Args.notNull(revocationTime, "revocationTime"), null);
  }

  public CertRevocationInfo revocationInfo() {
    return revocationInfo;
  }

  public Instant notBefore() {
    return notBefore;
  }

  public X509Cert cert() {
    return cert;
  }

  @Override
  public int hashCode() {
    return id.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }

    if (!(obj instanceof EjbcaIssuerEntry)) {
      return false;
    }

    EjbcaIssuerEntry other = (EjbcaIssuerEntry) obj;
    return id.equals(other.id)
            && CompareUtil.equals(revocationInfo, other.revocationInfo);
    // The comparison of id implies the comparison of issuerHashMap, notBefore
    // and cert.
  } // method equals

}
