package org.xipki.ca.gateway.acme.msg;

public class RevokeCertPayload {

  private Integer reason;

  private String certificate;

  public Integer getReason() {
    return reason;
  }

  public void setReason(Integer reason) {
    this.reason = reason;
  }

  public String getCertificate() {
    return certificate;
  }

  public void setCertificate(String certificate) {
    this.certificate = certificate;
  }
}
