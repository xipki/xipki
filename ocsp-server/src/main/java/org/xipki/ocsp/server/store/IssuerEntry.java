// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.store;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.asn1.Asn1Encoding;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.ocsp.api.RequestIssuer;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.pkix.cert.CertRevocationInfo;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.misc.CompareUtil;

import java.security.cert.CertificateEncodingException;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Issuer entry.
 *
 * @author Lijun Liao (xipki)
 */
public class IssuerEntry {

  private static final Logger LOG = LoggerFactory.getLogger(IssuerEntry.class);

  private final int id;

  private final Map<HashAlgo, byte[]> issuerHashMap;

  private final Instant notBefore;

  private final X509Cert cert;

  private int crlId;

  private CertRevocationInfo revocationInfo;

  public IssuerEntry(int id, X509Cert cert) throws CertificateEncodingException {
    this.id = id;
    this.cert = Args.notNull(cert, "cert");
    this.notBefore = cert.notBefore();
    this.issuerHashMap = getIssuerHashAndKeys(cert.getEncoded());
  }

  private static Map<HashAlgo, byte[]> getIssuerHashAndKeys(byte[] encodedCert)
      throws CertificateEncodingException {
    byte[] encodedName;
    byte[] encodedKey;
    try {
      Certificate bcCert = Certificate.fromEncoded(encodedCert);
      encodedName = bcCert.getSubject().getEncoded(Asn1Encoding.DER);
      encodedKey  = bcCert.getSubjectPublicKeyInfo().subjectPublicKey();
    } catch (IllegalArgumentException | CodecException ex) {
      throw new CertificateEncodingException(ex.getMessage(), ex);
    }

    Map<HashAlgo, byte[]> hashes = new HashMap<>();
    for (HashAlgo ha : HashAlgo.values()) {
      try {
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
      } catch (Exception e) {
        LOG.warn("could not compute hash of {}", ha, e);
      }
    }
    return hashes;
  } // method getIssuerHashAndKeys

  public int id() {
    return id;
  }

  public byte[] getEncodedHash(HashAlgo hashAlgo) {
    byte[] data = issuerHashMap.get(hashAlgo);
    if (data == null) {
      return null;
    }
    return Arrays.copyOf(data, data.length);
  }

  public boolean matchHash(RequestIssuer reqIssuer) {
    byte[] issuerHash = issuerHashMap.get(reqIssuer.hashAlgorithm());
    if (issuerHash == null) {
      return false;
    }

    return CompareUtil.areEqual(issuerHash, 0, reqIssuer.data(),
        reqIssuer.nameHashFrom(), issuerHash.length);
  }

  public void setRevocationInfo(Instant revocationTime) {
    this.revocationInfo = new CertRevocationInfo(CrlReason.CA_COMPROMISE,
        Args.notNull(revocationTime, "revocationTime"), null);
  }

  public CertRevocationInfo revocationInfo() {
    return revocationInfo;
  }

  public int crlId() {
    return crlId;
  }

  public void setCrlId(int crlId) {
    this.crlId = crlId;
  }

  public Instant notBefore() {
    return notBefore;
  }

  public X509Cert cert() {
    return cert;
  }

}
