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

package org.xipki.cmpclient.internal;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class RemoveExpiredCertsResult {

  private int numOfCerts;

  private long expiredAt;

  private String userLike;

  private String certprofile;

  public int getNumOfCerts() {
    return numOfCerts;
  }

  public void setNumOfCerts(int numOfCerts) {
    this.numOfCerts = numOfCerts;
  }

  public long getExpiredAt() {
    return expiredAt;
  }

  public void setExpiredAt(long expiredAt) {
    this.expiredAt = expiredAt;
  }

  public String getUserLike() {
    return userLike;
  }

  public void setUserLike(String userLike) {
    this.userLike = userLike;
  }

  public String getCertprofile() {
    return certprofile;
  }

  public void setCertprofile(String certprofile) {
    this.certprofile = certprofile;
  }

}
