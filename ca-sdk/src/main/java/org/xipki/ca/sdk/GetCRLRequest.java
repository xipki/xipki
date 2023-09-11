// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import java.math.BigInteger;

/**
 *
 * @author Lijun Liao (xipki)
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
    return CBOR.parseObject(encoded, GetCRLRequest.class);
  }

}
