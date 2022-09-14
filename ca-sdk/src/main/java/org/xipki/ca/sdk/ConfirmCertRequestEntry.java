/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

package org.xipki.ca.sdk;

import java.math.BigInteger;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class ConfirmCertRequestEntry {

  private BigInteger certReqId;

  /**
   * certHash.
   */
  private byte[] certhash;

  private boolean accept;

  public BigInteger getCertReqId() {
    return certReqId;
  }

  public void setCertReqId(BigInteger certReqId) {
    this.certReqId = certReqId;
  }

  public byte[] getCerthash() {
    return certhash;
  }

  public void setCerthash(byte[] certhash) {
    this.certhash = certhash;
  }

  public boolean isAccept() {
    return accept;
  }

  public void setAccept(boolean accept) {
    this.accept = accept;
  }

}
