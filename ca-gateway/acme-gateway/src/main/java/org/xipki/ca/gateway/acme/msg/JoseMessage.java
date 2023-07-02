package org.xipki.ca.gateway.acme.msg;

public class JoseMessage {

  @com.google.gson.annotations.SerializedName("protected")
  private String protected_;

  private String payload;

  private String signature;

  public String getProtected() {
    return protected_;
  }

  public void setProtected(String protected_) {
    this.protected_ = protected_;
  }

  public String getPayload() {
    return payload;
  }

  public void setPayload(String payload) {
    this.payload = payload;
  }

  public String getSignature() {
    return signature;
  }

  public void setSignature(String signature) {
    this.signature = signature;
  }

}
