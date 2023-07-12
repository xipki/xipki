// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.msg;

import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class NewAccountPayload {

  private Boolean termsOfServiceAgreed;

  private Boolean onlyReturnExisting;

  private List<String> contact;

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

  public List<String> getContact() {
    return contact;
  }

  public void setContact(List<String> contact) {
    this.contact = contact;
  }

  public JoseMessage getExternalAccountBinding() {
    return externalAccountBinding;
  }

  public void setExternalAccountBinding(JoseMessage externalAccountBinding) {
    this.externalAccountBinding = externalAccountBinding;
  }
}
