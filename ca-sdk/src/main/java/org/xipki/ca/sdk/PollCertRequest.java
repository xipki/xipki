package org.xipki.ca.sdk;

import com.alibaba.fastjson.JSON;

import java.util.List;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class PollCertRequest extends SdkRequest {

  private String transactionId;

  public X500NameType issuer;

  public byte[] subjectKeyIdentifier;

  private List<PollCertRequestEntry> entries;

  public String getTransactionId() {
    return transactionId;
  }

  public void setTransactionId(String transactionId) {
    this.transactionId = transactionId;
  }

  public List<PollCertRequestEntry> getEntries() {
    return entries;
  }

  public void setEntries(List<PollCertRequestEntry> entries) {
    this.entries = entries;
  }

  public X500NameType getIssuer() {
    return issuer;
  }

  public void setIssuer(X500NameType issuer) {
    this.issuer = issuer;
  }

  public byte[] getSubjectKeyIdentifier() {
    return subjectKeyIdentifier;
  }

  public void setSubjectKeyIdentifier(byte[] subjectKeyIdentifier) {
    this.subjectKeyIdentifier = subjectKeyIdentifier;
  }

  public static PollCertRequest decode(byte[] encoded) {
    return JSON.parseObject(encoded, PollCertRequest.class);
  }

}
