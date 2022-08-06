package org.xipki.ca.sdk;

import com.alibaba.fastjson.JSON;

import java.util.List;

public class EnrollCertsRequest extends CertsRequest {

  private List<EnrollCertRequestEntry> entries;

  public List<EnrollCertRequestEntry> getEntries() {
    return entries;
  }

  public void setEntries(List<EnrollCertRequestEntry> entries) {
    this.entries = entries;
  }

  public static EnrollCertsRequest decode(byte[] encoded) {
    return JSON.parseObject(encoded, EnrollCertsRequest.class);
  }

}
