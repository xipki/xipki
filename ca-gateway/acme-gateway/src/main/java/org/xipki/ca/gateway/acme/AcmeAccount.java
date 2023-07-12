// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.msg.AccountResponse;
import org.xipki.ca.gateway.acme.msg.JoseMessage;
import org.xipki.ca.gateway.acme.type.AccountStatus;
import org.xipki.ca.gateway.acme.util.AcmeUtils;
import org.xipki.util.Args;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeAccount {

  public static class Data {

    private Map<String, String> jwk;

    private List<String> contact;

    private JoseMessage externalAccountBinding;

    private Boolean termsOfServiceAgreed;

  }

  private boolean inDb;

  private boolean marked;

  private AcmeAccount mark;

  private final long id;

  private final String idStr;

  private String jwkSha256;

  private AccountStatus status;

  private PublicKey publicKey;

  private final AcmeDataSource dataSource;

  private Data data;

  public AcmeAccount(long id, AcmeDataSource dataSource) {
    this.id = id;
    this.idStr = AcmeUtils.toBase64(id);
    this.dataSource = Args.notNull(dataSource, "dataSource");
    this.data = new Data();
  }

  public void setInDb(boolean inDb) {
    this.inDb = inDb;
  }

  public boolean hasJwk(Map<String, String> jwk) {
    return jwk != null && jwk.equals(data.jwk);
  }

  public long getId() {
    return id;
  }

  public String getJwkSha256() {
    if (jwkSha256 == null && data.jwk != null) {
      jwkSha256 = AcmeUtils.jwkSha256(data.jwk);
    }
    return jwkSha256;
  }

  public void setJwkSha256(String jwkSha256) {
    markMe();
    this.jwkSha256 = jwkSha256;
  }

  public synchronized PublicKey getPublicKey() throws InvalidKeySpecException {
    if (publicKey == null && data.jwk != null) {
      publicKey = AcmeUtils.jwkPublicKey(data.jwk);
    }
    return publicKey;
  }

  public void setJwk(Map<String, String> jwk) {
    markMe();
    this.data.jwk = jwk;
  }

  public AccountStatus getStatus() {
    return status;
  }

  public void setStatus(AccountStatus status) {
    markMe();
    this.status = status;
  }

  public Data getData() {
    return data;
  }

  public void setData(Data data) {
    this.data = data;
  }

  public List<String> getContact() {
    return data.contact;
  }

  public void setContact(List<String> contact) {
    markMe();
    this.data.contact = contact;
  }

  public JoseMessage getExternalAccountBinding() {
    return data.externalAccountBinding;
  }

  public void setExternalAccountBinding(JoseMessage externalAccountBinding) {
    markMe();
    this.data.externalAccountBinding = externalAccountBinding;
  }

  public Boolean getTermsOfServiceAgreed() {
    return data.termsOfServiceAgreed;
  }

  public void setTermsOfServiceAgreed(Boolean termsOfServiceAgreed) {
    markMe();
    this.data.termsOfServiceAgreed = termsOfServiceAgreed;
  }

  public AccountResponse toResponse(String baseUrl) {
    AccountResponse resp = new AccountResponse();
    resp.setContact(data.contact);
    resp.setOrders(baseUrl + "orders/" + idStr);
    resp.setStatus(status);
    resp.setExternalAccountBinding(data.externalAccountBinding);
    resp.setTermsOfServiceAgreed(data.termsOfServiceAgreed);
    return resp;
  }

  public String getLocation(String baseUrl) {
    return baseUrl + "acct/" + idStr;
  }

  public void mark() {
    this.marked = true;
  }

  // do not throws any exception
  public synchronized void flush() {
    if (inDb) {
      if (mark != null) {
        dataSource.updateAccount(mark, this);
      }
    } else {
      // not saved in database.
      dataSource.addNewAccount(this);
      inDb = true;
    }

    mark = null;
  }

  private synchronized void markMe() {
    if (!inDb || mark != null) {
      return;
    }

    AcmeAccount copy = new AcmeAccount(id, dataSource);
    copy.setJwkSha256(jwkSha256);
    copy.data = new Data();
    copy.setJwk(new HashMap<>(data.jwk));
    copy.setStatus(status);
    copy.setTermsOfServiceAgreed(data.termsOfServiceAgreed);
    if (data.externalAccountBinding != null) {
      copy.setExternalAccountBinding(data.externalAccountBinding.copy());
    }
    if (data.contact != null) {
      copy.setContact(new ArrayList<>(data.contact));
    }
    copy.inDb = inDb;
    copy.marked = marked;

    this.mark = copy;
  }

}
