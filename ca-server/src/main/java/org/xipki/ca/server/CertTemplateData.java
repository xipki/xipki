// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.util.codec.Args;

import java.math.BigInteger;
import java.time.Instant;

/**
 * Certificate template data.
 *
 * @author Lijun Liao (xipki)
 */

public class CertTemplateData {

  private final X500Name subject;

  private final SubjectPublicKeyInfo publicKeyInfo;

  private final Instant notBefore;

  private final Instant notAfter;

  private final String certprofileName;

  private final boolean serverkeygen;

  private final Extensions extensions;

  private final BigInteger certReqId;

  private boolean forCrossCert;

  public CertTemplateData(
      X500Name subject, SubjectPublicKeyInfo publicKeyInfo, Instant notBefore,
      Instant notAfter, Extensions extensions, String certprofileName) {
    this(subject, publicKeyInfo, notBefore, notAfter, extensions,
        certprofileName, null, false);
  }

  public CertTemplateData(
      X500Name subject, SubjectPublicKeyInfo publicKeyInfo,
      Instant notBefore, Instant notAfter, Extensions extensions,
      String certprofileName, BigInteger certReqId, boolean serverkeygen) {
    this.publicKeyInfo = publicKeyInfo;
    this.subject = Args.notNull(subject, "subject");
    this.certprofileName = Args.toNonBlankLower(certprofileName,
        "certprofileName");
    this.extensions = extensions;
    this.notBefore = notBefore;
    this.notAfter = notAfter;
    this.certReqId = certReqId;
    this.serverkeygen = serverkeygen;
  }

  public boolean isForCrossCert() {
    return forCrossCert;
  }

  public void setForCrossCert(boolean forCrossCert) {
    this.forCrossCert = forCrossCert;
  }

  public X500Name subject() {
    return subject;
  }

  public SubjectPublicKeyInfo publicKeyInfo() {
    return publicKeyInfo;
  }

  public boolean isServerkeygen() {
    return serverkeygen;
  }

  public Instant notBefore() {
    return notBefore;
  }

  public Instant notAfter() {
    return notAfter;
  }

  public String certprofileName() {
    return certprofileName;
  }

  public Extensions extensions() {
    return extensions;
  }

  public BigInteger certReqId() {
    return certReqId;
  }

}
