package org.xipki.ca.sdk;

import com.alibaba.fastjson.JSON;

import java.util.List;

public class RevokeCertsRequest extends ChangeCertStatusRequest {

  private List<RevokeCertRequestEntry> entries;

  public List<RevokeCertRequestEntry> getEntries() {
    return entries;
  }

  public void setEntries(List<RevokeCertRequestEntry> entries) {
    this.entries = entries;
  }

  public static RevokeCertsRequest decode(byte[] encoded) {
    return JSON.parseObject(encoded, RevokeCertsRequest.class);
  }

}
