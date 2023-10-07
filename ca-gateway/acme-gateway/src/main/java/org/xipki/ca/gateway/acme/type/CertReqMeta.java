// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.type;

import org.xipki.util.CompareUtil;

import java.time.Instant;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class CertReqMeta {

  private Instant notBefore;

  private Instant notAfter;

  private String ca;

  private String certProfile;

  private String subject;

  public String getCa() {
    return ca;
  }

  public void setCa(String ca) {
    this.ca = ca;
  }

  public String getCertProfile() {
    return certProfile;
  }

  public void setCertProfile(String certProfile) {
    this.certProfile = certProfile;
  }

  public Instant getNotBefore() {
    return notBefore;
  }

  public void setNotBefore(Instant notBefore) {
    this.notBefore = notBefore;
  }

  public Instant getNotAfter() {
    return notAfter;
  }

  public void setNotAfter(Instant notAfter) {
    this.notAfter = notAfter;
  }

  public String getSubject() {
    return subject;
  }

  public void setSubject(String subject) {
    this.subject = subject;
  }

  @Override
  public boolean equals(Object other) {
    if (!(other instanceof CertReqMeta)) {
      return false;
    }

    CertReqMeta b = (CertReqMeta) other;
    return CompareUtil.equalsObject(ca, b.ca)
        && CompareUtil.equalsObject(certProfile, b.certProfile)
        && CompareUtil.equalsObject(subject, b.subject)
        && CompareUtil.equalsObject(notBefore, b.notBefore)
        && CompareUtil.equalsObject(notAfter, b.notAfter);
  }

  public CertReqMeta copy() {
    CertReqMeta copy = new CertReqMeta();

    copy.ca = ca;
    copy.certProfile = certProfile;
    copy.notAfter = notAfter;
    copy.notBefore = notBefore;
    copy.subject = subject;
    return copy;
  }

}
