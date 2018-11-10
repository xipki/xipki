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

package org.xipki.ca.mgmt.api;

import java.math.BigInteger;
import java.util.Date;

import org.xipki.util.ParamUtil;

/**
 * TODO.
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
    this.serialNumber = ParamUtil.requireNonNull("serialNumber", serialNumber);
    this.notBefore = ParamUtil.requireNonNull("notBefore", notBefore);
    this.notAfter = ParamUtil.requireNonNull("notAfter", notAfter);
    this.subject = ParamUtil.requireNonNull("subject", subject);
  }

  public void setSerialNumber(BigInteger serialNumber) {
    this.serialNumber = ParamUtil.requireNonNull("serialNumber", serialNumber);
  }

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public void setNotBefore(Date notBefore) {
    this.notBefore = ParamUtil.requireNonNull("notBefore", notBefore);
  }

  public Date getNotBefore() {
    return notBefore;
  }

  public void setNotAfter(Date notAfter) {
    this.notAfter = ParamUtil.requireNonNull("notAfter", notAfter);
  }

  public Date getNotAfter() {
    return notAfter;
  }

  public void setSubject(String subject) {
    this.subject = ParamUtil.requireNonNull("subject", subject);
  }

  public String getSubject() {
    return subject;
  }

}
