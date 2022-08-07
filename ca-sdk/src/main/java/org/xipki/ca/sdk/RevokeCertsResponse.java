package org.xipki.ca.sdk;

import com.alibaba.fastjson.JSON;

import java.util.List;

/**
 * Response for the operation revoking certificates.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class RevokeCertsResponse extends SdkResponse {

  private List<SingleCertSerialEntry> entries;

  public List<SingleCertSerialEntry> getEntries() {
    return entries;
  }

  public void setEntries(List<SingleCertSerialEntry> entries) {
    this.entries = entries;
  }

  public static RevokeCertsResponse decode(byte[] encoded) {
    return JSON.parseObject(encoded, RevokeCertsResponse.class);
  }

}
