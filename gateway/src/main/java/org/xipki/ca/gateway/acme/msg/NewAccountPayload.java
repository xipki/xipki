// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.msg;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class NewAccountPayload implements JsonEncodable {

  private final Boolean termsOfServiceAgreed;

  private final Boolean onlyReturnExisting;

  private final List<String> contact;

  private final JoseMessage externalAccountBinding;

  public NewAccountPayload(Boolean termsOfServiceAgreed,
                           Boolean onlyReturnExisting,
                           List<String> contact,
                           JoseMessage externalAccountBinding) {
    this.termsOfServiceAgreed = termsOfServiceAgreed;
    this.onlyReturnExisting = onlyReturnExisting;
    this.contact = contact;
    this.externalAccountBinding = externalAccountBinding;
  }

  public Boolean getTermsOfServiceAgreed() {
    return termsOfServiceAgreed;
  }

  public Boolean getOnlyReturnExisting() {
    return onlyReturnExisting;
  }

  public List<String> getContact() {
    return contact;
  }

  public JoseMessage getExternalAccountBinding() {
    return externalAccountBinding;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap()
        .put("termsOfServiceAgreed", termsOfServiceAgreed)
        .put("onlyReturnExisting", onlyReturnExisting)
        .putStrings("contact", contact)
        .put("externalAccountBinding", externalAccountBinding);
  }

  public static NewAccountPayload parse(JsonMap json) throws CodecException {
    JsonMap map = json.getMap("externalAccountBinding");
    JoseMessage externalAccountBinding = (map == null) ? null
        : JoseMessage.parse(map);
    return new NewAccountPayload(json.getBool("termsOfServiceAgreed"),
        json.getBool("onlyReturnExisting"),
        json.getStringList("contact"),
        externalAccountBinding);
  }

}
