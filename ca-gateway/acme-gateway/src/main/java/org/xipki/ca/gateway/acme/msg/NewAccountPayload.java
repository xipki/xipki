package org.xipki.ca.gateway.acme.msg;

public class NewAccountPayload {

  private Boolean termsOfServiceAgreed;

  private Boolean onlyReturnExisting;

  private String[] contact;

  private JoseMessage externalAccountBinding;


  public Boolean getTermsOfServiceAgreed() {
    return termsOfServiceAgreed;
  }

  public void setTermsOfServiceAgreed(Boolean termsOfServiceAgreed) {
    this.termsOfServiceAgreed = termsOfServiceAgreed;
  }

  public Boolean getOnlyReturnExisting() {
    return onlyReturnExisting;
  }

  public void setOnlyReturnExisting(Boolean onlyReturnExisting) {
    this.onlyReturnExisting = onlyReturnExisting;
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
}
