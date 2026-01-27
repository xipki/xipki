// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.msg;

import org.xipki.ca.gateway.acme.type.AccountStatus;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AccountResponse implements JsonEncodable {

  private final AccountStatus status;

  private final List<String> contact;

  private final JoseMessage externalAccountBinding;

  private final Boolean termsOfServiceAgreed;

  private final String orders;

  public AccountResponse(AccountStatus status, List<String> contact,
                         JoseMessage externalAccountBinding,
                         Boolean termsOfServiceAgreed, String orders) {
    this.status = status;
    this.contact = contact;
    this.externalAccountBinding = externalAccountBinding;
    this.termsOfServiceAgreed = termsOfServiceAgreed;
    this.orders = orders;
  }

  public AccountStatus getStatus() {
    return status;
  }

  public List<String> getContact() {
    return contact;
  }

  public JoseMessage getExternalAccountBinding() {
    return externalAccountBinding;
  }

  public Boolean getTermsOfServiceAgreed() {
    return termsOfServiceAgreed;
  }

  public String getOrders() {
    return orders;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().putEnum("status", status)
        .putStrings("contact", contact)
        .put("externalAccountBinding", externalAccountBinding)
        .put("termsOfServiceAgreed", termsOfServiceAgreed)
        .put("orders", orders);
  }

  public static AccountResponse parse(JsonMap json) throws CodecException {
    AccountStatus status = json.getEnum("status", AccountStatus.class);
    JsonMap map = json.getMap("externalAccountBinding");
    JoseMessage externalAccountBinding = (map == null) ? null
        : JoseMessage.parse(map);
    return new AccountResponse(status, json.getStringList("contact"),
        externalAccountBinding, json.getBool("termsOfServiceAgreed"),
        json.getString("orders"));
  }

}
