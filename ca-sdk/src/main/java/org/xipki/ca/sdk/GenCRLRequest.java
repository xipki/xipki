package org.xipki.ca.sdk;

import com.alibaba.fastjson.JSON;

public class GenCRLRequest extends SdkRequest {

  /**
   * Returns CRL published under this CRL distribution point.
   */
  private String crlDp;

  public String getCrlDp() {
    return crlDp;
  }

  public void setCrlDp(String crlDp) {
    this.crlDp = crlDp;
  }

  public static GenCRLRequest decode(byte[] encoded) {
    return JSON.parseObject(encoded, GenCRLRequest.class);
  }

}
