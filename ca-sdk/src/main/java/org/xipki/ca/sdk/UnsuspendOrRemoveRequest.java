package org.xipki.ca.sdk;

import com.alibaba.fastjson.JSON;

import java.math.BigInteger;
import java.util.List;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class UnsuspendOrRemoveRequest extends ChangeCertStatusRequest {

  private List<BigInteger> entries;

  public List<BigInteger> getEntries() {
    return entries;
  }

  public void setEntries(List<BigInteger> entries) {
    this.entries = entries;
  }

  public static UnsuspendOrRemoveRequest decode(byte[] encoded) {
    return JSON.parseObject(encoded, UnsuspendOrRemoveRequest.class);
  }

}
