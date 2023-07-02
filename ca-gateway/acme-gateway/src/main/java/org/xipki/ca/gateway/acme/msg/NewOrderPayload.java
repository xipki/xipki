package org.xipki.ca.gateway.acme.msg;

import org.xipki.ca.gateway.acme.type.Identifier;

public class NewOrderPayload {

  private Identifier[] identifiers;

  private String notBefore;

  private String notAfter;

  public Identifier[] getIdentifiers() {
    return identifiers;
  }

  public void setIdentifiers(Identifier[] identifiers) {
    this.identifiers = identifiers;
  }

  public String getNotBefore() {
    return notBefore;
  }

  public void setNotBefore(String notBefore) {
    this.notBefore = notBefore;
  }

  public String getNotAfter() {
    return notAfter;
  }

  public void setNotAfter(String notAfter) {
    this.notAfter = notAfter;
  }

}
