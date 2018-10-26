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

package org.xipki.ca.server.mgmt.msg;

import java.util.Date;

/**
 * TODO.
 * @author Lijun Liao
 */

public class GenerateCertificateRequest extends CaNameRequest {

  private String profileName;

  private byte[] encodedCsr;

  private Date notBefore;

  private Date notAfter;

  public String getProfileName() {
    return profileName;
  }

  public void setProfileName(String profileName) {
    this.profileName = profileName;
  }

  public byte[] getEncodedCsr() {
    return encodedCsr;
  }

  public void setEncodedCsr(byte[] encodedCsr) {
    this.encodedCsr = encodedCsr;
  }

  public Date getNotBefore() {
    return notBefore;
  }

  public void setNotBefore(Date notBefore) {
    this.notBefore = notBefore;
  }

  public Date getNotAfter() {
    return notAfter;
  }

  public void setNotAfter(Date notAfter) {
    this.notAfter = notAfter;
  }

}
