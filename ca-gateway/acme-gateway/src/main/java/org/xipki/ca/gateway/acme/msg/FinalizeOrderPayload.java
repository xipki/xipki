package org.xipki.ca.gateway.acme.msg;

public class FinalizeOrderPayload {

  private String csr;

  public String getCsr() {
    return csr;
  }

  public void setCsr(String csr) {
    this.csr = csr;
  }

}
