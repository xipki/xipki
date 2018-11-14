/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.api;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertificateInfo {

  private final byte[] subjectPublicKey;

  private final CertWithDbId cert;

  private final PrivateKeyInfo privateKey;

  private final NameId issuer;

  private final X509Cert issuerCert;

  private final NameId profile;

  private final NameId requestor;

  private RequestType reqType;

  private byte[] transactionId;

  private Integer user;

  private String warningMessage;

  private CertRevocationInfo revocationInfo;

  private X500Name requestedSubject;

  private boolean alreadyIssued;

  public CertificateInfo(CertWithDbId cert, PrivateKeyInfo privateKey, NameId issuer,
      X509Cert issuerCert, byte[] subjectPublicKey, NameId profile, NameId requestor) {
    this.profile = Args.notNull(profile, "profile");
    this.cert = Args.notNull(cert, "cert");
    this.privateKey = privateKey;
    this.subjectPublicKey = Args.notNull(subjectPublicKey, "subjectPublicKey");
    this.issuer = Args.notNull(issuer, "issuer");
    this.issuerCert = Args.notNull(issuerCert, "issuerCert");
    this.requestor = Args.notNull(requestor, "requestor");
  }

  public byte[] getSubjectPublicKey() {
    return subjectPublicKey;
  }

  public CertWithDbId getCert() {
    return cert;
  }

  public PrivateKeyInfo getPrivateKey() {
    return privateKey;
  }

  public NameId getIssuer() {
    return issuer;
  }

  public X509Cert getIssuerCert() {
    return issuerCert;
  }

  public NameId getProfile() {
    return profile;
  }

  public String getWarningMessage() {
    return warningMessage;
  }

  public void setWarningMessage(String warningMessage) {
    this.warningMessage = warningMessage;
  }

  public NameId getRequestor() {
    return requestor;
  }

  public Integer getUser() {
    return user;
  }

  public void setUser(Integer user) {
    this.user = user;
  }

  public boolean isRevoked() {
    return revocationInfo != null;
  }

  public CertRevocationInfo getRevocationInfo() {
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

  public RequestType getReqType() {
    return reqType;
  }

  public void setReqType(RequestType reqType) {
    this.reqType = reqType;
  }

  public byte[] getTransactionId() {
    return transactionId;
  }

  public void setTransactionId(byte[] transactionId) {
    this.transactionId = transactionId;
  }

  public X500Name getRequestedSubject() {
    return requestedSubject;
  }

  public void setRequestedSubject(X500Name requestedSubject) {
    this.requestedSubject = requestedSubject;
  }

}
