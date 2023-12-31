// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.util.Args;
import org.xipki.util.DateUtil;

import java.math.BigInteger;
import java.time.Instant;

/**
 * Certificate list container.
 *
 * @author Lijun Liao (xipki)
 * @since 2.1.0
 */

public class CertListInfo {
  private BigInteger serialNumber;

  private String notBefore;

  private String notAfter;

  private String subject;

  // For the deserialization only
  @SuppressWarnings("unused")
  private CertListInfo() {
  }

  public CertListInfo(BigInteger serialNumber, String subject, Instant notBefore, Instant notAfter) {
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
    this.notBefore = DateUtil.toUtcTimeyyyyMMddhhmmss(Args.notNull(notBefore, "notBefore"));
    this.notAfter = DateUtil.toUtcTimeyyyyMMddhhmmss(Args.notNull(notAfter, "notAfter"));
    this.subject = Args.notNull(subject, "subject");
  }

  public void setSerialNumber(BigInteger serialNumber) {
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
  }

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public void setNotBefore(String notBefore) {
    this.notBefore = Args.notNull(notBefore, "notBefore");
  }

  public String getNotBefore() {
    return notBefore;
  }

  public void setNotAfter(String notAfter) {
    this.notAfter = Args.notNull(notAfter, "notAfter");
  }

  public String getNotAfter() {
    return notAfter;
  }

  public void setSubject(String subject) {
    this.subject = Args.notNull(subject, "subject");
  }

  public String getSubject() {
    return subject;
  }

}
