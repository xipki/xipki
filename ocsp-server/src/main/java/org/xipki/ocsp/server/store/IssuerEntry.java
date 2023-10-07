// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.store;

import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.ocsp.api.RequestIssuer;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;
import org.xipki.util.CompareUtil;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Issuer entry.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class IssuerEntry {

  private final int id;

  private final Map<HashAlgo, byte[]> issuerHashMap;

  private final Instant notBefore;

  private final X509Cert cert;

  private int crlId;

  private CertRevocationInfo revocationInfo;

  public IssuerEntry(int id, X509Cert cert) throws CertificateEncodingException {
    this.id = id;
    this.cert = Args.notNull(cert, "cert");
    this.notBefore = cert.getNotBefore();
    this.issuerHashMap = getIssuerHashAndKeys(cert.getEncoded());
  }

  private static Map<HashAlgo, byte[]> getIssuerHashAndKeys(byte[] encodedCert)
      throws CertificateEncodingException {
    byte[] encodedName;
    byte[] encodedKey;
    try {
      Certificate bcCert = Certificate.getInstance(encodedCert);
      encodedName = bcCert.getSubject().getEncoded("DER");
      encodedKey = bcCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
    } catch (IllegalArgumentException | IOException ex) {
      throw new CertificateEncodingException(ex.getMessage(), ex);
    }

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
  } // method getIssuerHashAndKeys

  public int getId() {
    return id;
  }

  public byte[] getEncodedHash(HashAlgo hashAlgo) {
    byte[] data = issuerHashMap.get(hashAlgo);
    return Arrays.copyOf(data, data.length);
  }

  public boolean matchHash(RequestIssuer reqIssuer) {
    byte[] issuerHash = issuerHashMap.get(reqIssuer.hashAlgorithm());
    if (issuerHash == null) {
      return false;
    }

    return CompareUtil.areEqual(issuerHash, 0, reqIssuer.getData(),
        reqIssuer.getNameHashFrom(), issuerHash.length);
  }

  public void setRevocationInfo(Instant revocationTime) {
    this.revocationInfo = new CertRevocationInfo(CrlReason.CA_COMPROMISE,
        Args.notNull(revocationTime, "revocationTime"), null);
  }

  public CertRevocationInfo getRevocationInfo() {
    return revocationInfo;
  }

  public int getCrlId() {
    return crlId;
  }

  public void setCrlId(int crlId) {
    this.crlId = crlId;
  }

  public Instant getNotBefore() {
    return notBefore;
  }

  public X509Cert getCert() {
    return cert;
  }

}
