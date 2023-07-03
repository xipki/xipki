// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.msg.AccountResponse;
import org.xipki.ca.gateway.acme.msg.JoseMessage;
import org.xipki.ca.gateway.acme.type.AccountStatus;
import org.xipki.ca.gateway.acme.util.AcmeUtils;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeAccount {

  private String label;

  private Map<String, String> jwk;

  private AccountStatus status;

  private String[] contact;

  private JoseMessage externalAccountBinding;

  private Boolean termsOfServiceAgreed;

  private PublicKey publicKey;

  public boolean hasJwk(Map<String, String> jwk) {
    return jwk != null && jwk.equals(this.jwk);
  }

  public String getLabel() {
    return label;
  }

  public void setLabel(String label) {
    this.label = label;
  }

  public synchronized PublicKey getPublicKey() throws InvalidKeySpecException {
    if (publicKey == null && jwk != null) {
      publicKey = AcmeUtils.jwkPublicKey(jwk);
    }
    return publicKey;
  }

  public void setJwk(Map<String, String> jwk) {
    this.jwk = jwk;
  }

  public Map<String, String> getJwk() {
    return jwk;
  }

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

  public AccountResponse toResponse(String baseUrl) {
    AccountResponse resp = new AccountResponse();
    resp.setContact(contact);
    resp.setOrders(baseUrl + "orders/" + label);
    resp.setStatus(status);
    resp.setExternalAccountBinding(externalAccountBinding);
    resp.setTermsOfServiceAgreed(termsOfServiceAgreed);
    return resp;
  }

  public String getLocation(String baseUrl) {
    return baseUrl + "acct/" + label;
  }

}
