package org.xipki.ca.gateway.acme.msg;

import org.xipki.ca.gateway.acme.type.AccountStatus;

public class AccountResponse {
  private AccountStatus status;

  private String[] contact;

  private JoseMessage externalAccountBinding;

  private Boolean termsOfServiceAgreed;

  private String orders;

  public AccountStatus getStatus() {
    return status;
  }

  public void setStatus(AccountStatus status) {
    this.status = status;
  }

  public String[] getContact() {
    return contact;
  }

  public void setContact(String[] contact) {
    this.contact = contact;
  }

  public JoseMessage getExternalAccountBinding() {
    return externalAccountBinding;
  }

  public void setExternalAccountBinding(JoseMessage externalAccountBinding) {
    this.externalAccountBinding = externalAccountBinding;
  }

  public Boolean getTermsOfServiceAgreed() {
    return termsOfServiceAgreed;
  }

  public void setTermsOfServiceAgreed(Boolean termsOfServiceAgreed) {
    this.termsOfServiceAgreed = termsOfServiceAgreed;
  }

  public String getOrders() {
    return orders;
  }

  public void setOrders(String orders) {
    this.orders = orders;
  }
}
