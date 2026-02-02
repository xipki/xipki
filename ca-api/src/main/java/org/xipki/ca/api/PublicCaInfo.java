// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.xipki.security.exception.OperationException;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.conf.ConfPairs;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Public CA information.
 *
 * @author Lijun Liao (xipki)
 */

public class PublicCaInfo {

  private final X500Name subject;

  private final String c14nSubject;

  private final byte[] subjectKeyIdentifier;

  private final GeneralNames subjectAltName;

  private final X500Name issuer;

  private final BigInteger serialNumber;

  private final X509Cert caCert;

  private X509Cert crlSignerCert;

  private final CaUris caUris;

  private final ConfPairs extraControl;

  public PublicCaInfo(X509Cert caCert, CaUris caUris, ConfPairs extraControl)
      throws OperationException {
    this.caCert = Args.notNull(caCert, "caCert");
    this.caUris = (caUris == null) ? CaUris.EMPTY_INSTANCE : caUris;
    this.issuer = caCert.issuer();
    this.serialNumber = caCert.serialNumber();
    this.subject = caCert.subject();
    this.c14nSubject = X509Util.canonicalizeName(subject);
    this.subjectKeyIdentifier = caCert.subjectKeyId();
    this.extraControl = extraControl;
    this.subjectAltName = (caCert.subjectAltNames() == null) ? null
        : GeneralNames.getInstance(caCert.subjectAltNames());
  } // constructor

  public PublicCaInfo(
      X500Name subject, X500Name issuer, BigInteger serialNumber,
      GeneralNames subjectAltName, byte[] subjectKeyIdentifier,
      CaUris caUris, ConfPairs extraControl) {
    this.subject = Args.notNull(subject, "subject");
    this.issuer = Args.notNull(issuer, "issuer");
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
    this.caUris = (caUris == null) ? CaUris.EMPTY_INSTANCE : caUris;

    this.caCert = null;
    this.c14nSubject = X509Util.canonicalizeName(subject);

    this.subjectKeyIdentifier = (subjectKeyIdentifier == null) ? null
        : Arrays.copyOf(subjectKeyIdentifier, subjectKeyIdentifier.length);

    this.subjectAltName = subjectAltName;
    this.extraControl = extraControl;
  } // constructor

  /**
   * Returns the CA URIs.
   * @return non-null CaUris.
   */
  public CaUris caUris() {
    return caUris;
  }

  public X509Cert crlSignerCert() {
    return crlSignerCert;
  }

  public void setCrlSignerCert(X509Cert crlSignerCert) {
    this.crlSignerCert = caCert.equals(crlSignerCert) ? null : crlSignerCert;
  }

  public X500Name subject() {
    return subject;
  }

  public X500Name issuer() {
    return issuer;
  }

  public String c14nSubject() {
    return c14nSubject;
  }

  public GeneralNames subjectAltName() {
    return subjectAltName;
  }

  public byte[] subjectKeyIdentifier() {
    return (subjectKeyIdentifier == null) ? null
        : Arrays.copyOf(subjectKeyIdentifier, subjectKeyIdentifier.length);
  }

  public BigInteger serialNumber() {
    return serialNumber;
  }

  public X509Cert caCert() {
    return caCert;
  }

  public ConfPairs extraControl() {
    return extraControl;
  }

}
