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

import com.alibaba.fastjson.JSON;

import java.math.BigInteger;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class GetCRLRequest extends SdkRequest {

  /**
   * Returns CRL of this specified crlNumber.
   */
  private BigInteger crlNumber;

  /**
   * Epoch time in seconds of thisUpdate of the known CRL.
   * If present, returns only CRL with larger thisUpdate.
   */
  private Long thisUpdate;

  /**
   * Returns CRL published under this CRL distribution point.
   */
  private String crlDp;

  public BigInteger getCrlNumber() {
    return crlNumber;
  }

  public void setCrlNumber(BigInteger crlNumber) {
    this.crlNumber = crlNumber;
  }

  public Long getThisUpdate() {
    return thisUpdate;
  }

  public void setThisUpdate(Long thisUpdate) {
    this.thisUpdate = thisUpdate;
  }

  public String getCrlDp() {
    return crlDp;
  }

  public void setCrlDp(String crlDp) {
    this.crlDp = crlDp;
  }

  public static GetCRLRequest decode(byte[] encoded) {
    return JSON.parseObject(encoded, GetCRLRequest.class);
  }

}
