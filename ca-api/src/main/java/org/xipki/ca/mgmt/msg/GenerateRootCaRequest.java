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

import java.math.BigInteger;

/**
 * TODO.
 * @author Lijun Liao
 */

public class GenerateRootCaRequest extends CommRequest {

  private CaEntryWrapper caEntry;

  private String certprofileName;

  private byte[] encodedCsr;

  private BigInteger serialNumber;

  public CaEntryWrapper getCaEntry() {
    return caEntry;
  }

  public void setCaEntry(CaEntryWrapper caEntry) {
    this.caEntry = caEntry;
  }

  public String getCertprofileName() {
    return certprofileName;
  }

  public void setCertprofileName(String certprofileName) {
    this.certprofileName = certprofileName;
  }

  public byte[] getEncodedCsr() {
    return encodedCsr;
  }

  public void setEncodedCsr(byte[] encodedCsr) {
    this.encodedCsr = encodedCsr;
  }

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public void setSerialNumber(BigInteger serialNumber) {
    this.serialNumber = serialNumber;
  }

}
