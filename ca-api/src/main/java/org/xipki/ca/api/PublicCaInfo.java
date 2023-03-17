// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.ConfPairs;
import org.xipki.util.exception.ErrorCode;
import org.xipki.util.exception.OperationException;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Public CA information.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
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
    this.issuer = caCert.getIssuer();
    this.serialNumber = caCert.getSerialNumber();
    this.subject = caCert.getSubject();
    this.c14nSubject = X509Util.canonicalizName(subject);
    this.subjectKeyIdentifier = caCert.getSubjectKeyId();
    this.extraControl = extraControl;

    byte[] encodedSubjectAltName = caCert.getExtensionCoreValue(Extension.subjectAlternativeName);
    if (encodedSubjectAltName == null) {
      subjectAltName = null;
    } else {
      try {
        subjectAltName = GeneralNames.getInstance(encodedSubjectAltName);
      } catch (RuntimeException ex) {
        throw new OperationException(ErrorCode.INVALID_EXTENSION, "invalid SubjectAltName extension in CA certificate");
      }
    }
  } // constructor

  public PublicCaInfo(X500Name subject, X500Name issuer, BigInteger serialNumber, GeneralNames subjectAltName,
                      byte[] subjectKeyIdentifier, CaUris caUris, ConfPairs extraControl) {
    this.subject = Args.notNull(subject, "subject");
    this.issuer = Args.notNull(issuer, "issuer");
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
    this.caUris = (caUris == null) ? CaUris.EMPTY_INSTANCE : caUris;

    this.caCert = null;
    this.c14nSubject = X509Util.canonicalizName(subject);

    this.subjectKeyIdentifier = (subjectKeyIdentifier == null) ? null
        : Arrays.copyOf(subjectKeyIdentifier, subjectKeyIdentifier.length);

    this.subjectAltName = subjectAltName;
    this.extraControl = extraControl;
  } // constructor

  /**
   * Returns the CA URIs.
   * @return non-null CaUris.
   */
  public CaUris getCaUris() {
    return caUris;
  }

  public X509Cert getCrlSignerCert() {
    return crlSignerCert;
  }

  public void setCrlSignerCert(X509Cert crlSignerCert) {
    this.crlSignerCert = caCert.equals(crlSignerCert) ? null : crlSignerCert;
  }

  public X500Name getSubject() {
    return subject;
  }

  public X500Name getIssuer() {
    return issuer;
  }

  public String getC14nSubject() {
    return c14nSubject;
  }

  public GeneralNames getSubjectAltName() {
    return subjectAltName;
  }

  public byte[] getSubjectKeyIdentifer() {
    return (subjectKeyIdentifier == null) ? null : Arrays.copyOf(subjectKeyIdentifier, subjectKeyIdentifier.length);
  }

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public X509Cert getCaCert() {
    return caCert;
  }

  public ConfPairs getExtraControl() {
    return extraControl;
  }

}
