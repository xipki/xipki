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

package org.xipki.ca.mgmt.msg;

import java.util.Date;

import org.xipki.ca.mgmt.api.CertListOrderBy;

/**
 * TODO.
 * @author Lijun Liao
 */

public class ListCertificatesRequest extends CaNameRequest {

  private byte[] encodedSubjectDnPattern;

  private Date validFrom;

  private Date validTo;

  private CertListOrderBy orderBy;

  private int numEntries;

  public byte[] getEncodedSubjectDnPattern() {
    return encodedSubjectDnPattern;
  }

  public void setEncodedSubjectDnPattern(byte[] encodedSubjectDnPattern) {
    this.encodedSubjectDnPattern = encodedSubjectDnPattern;
  }

  public Date getValidFrom() {
    return validFrom;
  }

  public void setValidFrom(Date validFrom) {
    this.validFrom = validFrom;
  }

  public Date getValidTo() {
    return validTo;
  }

  public void setValidTo(Date validTo) {
    this.validTo = validTo;
  }

  public CertListOrderBy getOrderBy() {
    return orderBy;
  }

  public void setOrderBy(CertListOrderBy orderBy) {
    this.orderBy = orderBy;
  }

  public int getNumEntries() {
    return numEntries;
  }

  public void setNumEntries(int numEntries) {
    this.numEntries = numEntries;
  }

}
