// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.msg.AccountResponse;
import org.xipki.ca.gateway.acme.msg.JoseMessage;
import org.xipki.ca.gateway.acme.type.AccountStatus;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

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

  public static class Data implements JsonEncodable {

    private Map<String, String> jwk;

    private List<String> contact;

    private JoseMessage externalAccountBinding;

    private Boolean termsOfServiceAgreed;

    public Data() {
    }

    public Data(Map<String, String> jwk, List<String> contact,
                JoseMessage externalAccountBinding,
                Boolean termsOfServiceAgreed) {
      this.jwk = jwk;
      this.contact = contact;
      this.externalAccountBinding = externalAccountBinding;
      this.termsOfServiceAgreed = termsOfServiceAgreed;
    }

    public Map<String, String> jwk() {
      return jwk;
    }

    public void setJwk(Map<String, String> jwk) {
      this.jwk = jwk;
    }

    public List<String> contact() {
      return contact;
    }

    public void setContact(List<String> contact) {
      this.contact = contact;
    }

    public JoseMessage externalAccountBinding() {
      return externalAccountBinding;
    }

    public void setExternalAccountBinding(JoseMessage externalAccountBinding) {
      this.externalAccountBinding = externalAccountBinding;
    }

    public Boolean termsOfServiceAgreed() {
      return termsOfServiceAgreed;
    }

    public void setTermsOfServiceAgreed(Boolean termsOfServiceAgreed) {
      this.termsOfServiceAgreed = termsOfServiceAgreed;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().putStringMap("jwk", jwk)
          .putStrings("contact", contact)
          .put("externalAccountBinding", externalAccountBinding)
          .put("termsOfServiceAgreed", termsOfServiceAgreed);
    }

    public static Data parse(JsonMap json) throws CodecException {
      JsonMap map = json.getMap("externalAccountBinding");
      JoseMessage externalAccountBinding = (map == null) ? null
          : JoseMessage.parse(map);
      return new Data(json.getStringMap("jwk"),
          json.getStringList("contact"),
          externalAccountBinding,
          json.getBool("termsOfServiceAgreed"));
    }

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

  public long id() {
    return id;
  }

  public String idText() {
    return idStr + " (" + id + ")";
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

  public AccountStatus status() {
    return status;
  }

  public void setStatus(AccountStatus status) {
    markMe();
    this.status = status;
  }

  public Data data() {
    return data;
  }

  public void setData(Data data) {
    this.data = data;
  }

  public List<String> contact() {
    return data.contact;
  }

  public void setContact(List<String> contact) {
    markMe();
    this.data.contact = contact;
  }

  public JoseMessage externalAccountBinding() {
    return data.externalAccountBinding;
  }

  public void setExternalAccountBinding(JoseMessage externalAccountBinding) {
    markMe();
    this.data.externalAccountBinding = externalAccountBinding;
  }

  public Boolean termsOfServiceAgreed() {
    return data.termsOfServiceAgreed;
  }

  public void setTermsOfServiceAgreed(Boolean termsOfServiceAgreed) {
    markMe();
    this.data.termsOfServiceAgreed = termsOfServiceAgreed;
  }

  public AccountResponse toResponse(String baseUrl) {
    return new AccountResponse(status, data.contact,
        data.externalAccountBinding, data.termsOfServiceAgreed,
        baseUrl + "orders/" + idStr);
  }

  public String getLocation(String baseUrl) {
    return baseUrl + "acct/" + idStr;
  }

  public void mark() {
    this.marked = true;
  }

  // do not throw any exception
  public synchronized void flush() throws AcmeSystemException {
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
    copy.inDb   = inDb;
    copy.marked = marked;

    this.mark = copy;
  }

}
