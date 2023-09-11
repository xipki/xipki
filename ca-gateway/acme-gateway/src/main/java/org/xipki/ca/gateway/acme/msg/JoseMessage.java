// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.msg;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class JoseMessage {

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

  public JoseMessage copy() {
    JoseMessage copy = new JoseMessage();
    copy.setProtected(protected_);
    copy.setPayload(payload);
    copy.setSignature(signature);
    return copy;
  }

}
