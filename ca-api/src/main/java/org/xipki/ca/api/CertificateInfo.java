// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.security.pkix.CertRevocationInfo;
import org.xipki.security.pkix.X509Cert;
import org.xipki.util.codec.Args;

/**
 * Certificate Information.
 *
 * @author Lijun Liao (xipki)
 */

public class CertificateInfo {

  private final CertWithDbId cert;

  private final PrivateKeyInfo privateKey;

  private final NameId issuer;

  private final X509Cert issuerCert;

  private final NameId profile;

  private final NameId requestor;

  private String transactionId;

  private String warningMessage;

  private CertRevocationInfo revocationInfo;

  private X500Name requestedSubject;

  private boolean alreadyIssued;

  public CertificateInfo(
      CertWithDbId cert, PrivateKeyInfo privateKey, NameId issuer,
      X509Cert issuerCert, NameId profile, NameId requestor) {
    this.profile = Args.notNull(profile, "profile");
    this.cert = Args.notNull(cert, "cert");
    this.privateKey = privateKey;
    this.issuer = Args.notNull(issuer, "issuer");
    this.issuerCert = Args.notNull(issuerCert, "issuerCert");
    this.requestor = Args.notNull(requestor, "requestor");
  }

  public CertWithDbId cert() {
    return cert;
  }

  public PrivateKeyInfo privateKey() {
    return privateKey;
  }

  public NameId issuer() {
    return issuer;
  }

  public X509Cert issuerCert() {
    return issuerCert;
  }

  public NameId profile() {
    return profile;
  }

  public String warningMessage() {
    return warningMessage;
  }

  public void setWarningMessage(String warningMessage) {
    this.warningMessage = warningMessage;
  }

  public NameId requestor() {
    return requestor;
  }

  public boolean isRevoked() {
    return revocationInfo != null;
  }

  public CertRevocationInfo revocationInfo() {
    return revocationInfo;
  }

  public void setRevocationInfo(CertRevocationInfo revocationInfo) {
    this.revocationInfo = revocationInfo;
  }

  public boolean isAlreadyIssued() {
    return alreadyIssued;
  }

  public void setAlreadyIssued(boolean alreadyIssued) {
    this.alreadyIssued = alreadyIssued;
  }

  public String transactionId() {
    return transactionId;
  }

  public void setTransactionId(String transactionId) {
    this.transactionId = transactionId;
  }

  public X500Name requestedSubject() {
    return requestedSubject;
  }

  public void setRequestedSubject(X500Name requestedSubject) {
    this.requestedSubject = requestedSubject;
  }

}
