package org.xipki.ca.sdk;

import com.alibaba.fastjson.JSON;

import java.math.BigInteger;

public class PayloadResponse extends SdkResponse {

  /**
   * payload.
   */
  private byte[] payload;

  public byte[] getPayload() {
    return payload;
  }

  public void setPayload(byte[] payload) {
    this.payload = payload;
  }

  public static PayloadResponse decode(byte[] encoded) {
    return JSON.parseObject(encoded, PayloadResponse.class);
  }

}
