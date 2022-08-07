package org.xipki.ca.sdk;

import com.alibaba.fastjson.JSON;

import java.util.List;

/**
 * Response for the operations unrevoking certificates and removing certificates.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class UnrevokeOrRemoveCertsResponse extends SdkResponse {

  private List<SingleCertSerialEntry> entries;

  public List<SingleCertSerialEntry> getEntries() {
    return entries;
  }

  public void setEntries(List<SingleCertSerialEntry> entries) {
    this.entries = entries;
  }

  public static UnrevokeOrRemoveCertsResponse decode(byte[] encoded) {
    return JSON.parseObject(encoded, UnrevokeOrRemoveCertsResponse.class);
  }

}
