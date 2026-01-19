// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.type;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.misc.CompareUtil;

import java.time.Instant;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class CertReqMeta implements JsonEncodable {

  private Instant notBefore;

  private Instant notAfter;

  private String ca;

  private String certProfile;

  private String subject;

  public CertReqMeta() {
  }

  public CertReqMeta(Instant notBefore, Instant notAfter, String ca,
                     String certProfile, String subject) {
    this.notBefore = notBefore;
    this.notAfter = notAfter;
    this.ca = ca;
    this.certProfile = certProfile;
    this.subject = subject;
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

  public String getSubject() {
    return subject;
  }

  public void setSubject(String subject) {
    this.subject = subject;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap()
        .put("notBefore", notBefore)
        .put("notAfter", notAfter)
        .put("ca", ca)
        .put("certProfile", certProfile)
        .put("subject", subject);
  }

  public static CertReqMeta parse(JsonMap json) throws CodecException {
    return new CertReqMeta(json.getInstant("notBefore"),
        json.getInstant("notAfter"), json.getString("ca"),
        json.getString("certProfile"), json.getString("subject"));
  }

  @Override
  public boolean equals(Object other) {
    if (!(other instanceof CertReqMeta)) {
      return false;
    }

    CertReqMeta b = (CertReqMeta) other;
    return CompareUtil.equals(ca, b.ca)
        && CompareUtil.equals(certProfile, b.certProfile)
        && CompareUtil.equals(subject, b.subject)
        && CompareUtil.equals(notBefore, b.notBefore)
        && CompareUtil.equals(notAfter, b.notAfter);
  }

  public CertReqMeta copy() {
    return new CertReqMeta(notBefore, notAfter, ca, certProfile, subject);
  }

}
