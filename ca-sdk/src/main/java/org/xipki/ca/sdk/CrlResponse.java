package org.xipki.ca.sdk;

import com.alibaba.fastjson.JSON;

/**
 * Response containing the CRL.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class CrlResponse extends SdkResponse {

  private byte[] crl;

  public byte[] getCrl() {
    return crl;
  }

  public void setCrl(byte[] crl) {
    this.crl = crl;
  }

  public static CrlResponse decode(byte[] encoded) {
    return JSON.parseObject(encoded, CrlResponse.class);
  }

}
