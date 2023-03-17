// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.util.Args;

import java.math.BigInteger;
import java.util.Date;

/**
 * Certificate list container.
 *
 * @author Lijun Liao
 * @since 2.1.0
 */

public class CertListInfo {
  private BigInteger serialNumber;

  private Date notBefore;

  private Date notAfter;

  private String subject;

  // For the deserialization only
  @SuppressWarnings("unused")
  private CertListInfo() {
  }

  public CertListInfo(BigInteger serialNumber, String subject, Date notBefore, Date notAfter) {
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
    this.notBefore = Args.notNull(notBefore, "notBefore");
    this.notAfter = Args.notNull(notAfter, "notAfter");
    this.subject = Args.notNull(subject, "subject");
  }

  public void setSerialNumber(BigInteger serialNumber) {
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
  }

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public void setNotBefore(Date notBefore) {
    this.notBefore = Args.notNull(notBefore, "notBefore");
  }

  public Date getNotBefore() {
    return notBefore;
  }

  public void setNotAfter(Date notAfter) {
    this.notAfter = Args.notNull(notAfter, "notAfter");
  }

  public Date getNotAfter() {
    return notAfter;
  }

  public void setSubject(String subject) {
    this.subject = Args.notNull(subject, "subject");
  }

  public String getSubject() {
    return subject;
  }

}
