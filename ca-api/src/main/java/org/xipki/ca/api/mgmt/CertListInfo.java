/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.ca.api.mgmt;

import java.math.BigInteger;
import java.util.Date;

import org.xipki.util.Args;

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
