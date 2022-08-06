package org.xipki.ca.sdk;

import com.alibaba.fastjson.JSON;

import java.util.List;

public class ConfirmCertsRequest extends SdkRequest {

  private String transactionId;

  private List<ConfirmCertRequestEntry> entries;

  public String getTransactionId() {
    return transactionId;
  }

  public void setTransactionId(String transactionId) {
    this.transactionId = transactionId;
  }

  public List<ConfirmCertRequestEntry> getEntries() {
    return entries;
  }

  public void setEntries(List<ConfirmCertRequestEntry> entries) {
    this.entries = entries;
  }

  public static ConfirmCertsRequest decode(byte[] encoded) {
    return JSON.parseObject(encoded, ConfirmCertsRequest.class);
  }

}
