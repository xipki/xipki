// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.msg;

import org.xipki.ca.gateway.acme.type.Identifier;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class NewOrderPayload implements JsonEncodable {

  private final List<Identifier> identifiers;

  private final String notBefore;

  private final String notAfter;

  public NewOrderPayload(List<Identifier> identifiers,
                         String notBefore, String notAfter) {
    this.identifiers = identifiers;
    this.notBefore = notBefore;
    this.notAfter = notAfter;
  }

  public List<Identifier> identifiers() {
    return identifiers;
  }

  public String notBefore() {
    return notBefore;
  }

  public String notAfter() {
    return notAfter;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().putEncodables("identifiers", identifiers)
        .put("notBefore", notBefore).put("notAfter", notAfter);
  }

  public static NewOrderPayload parse(JsonMap json) throws CodecException {
    JsonList list = json.getList("identifiers");
    List<Identifier> identifiers = null;
    if (list != null) {
      identifiers = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        identifiers.add(Identifier.parse(v));
      }
    }

    return new NewOrderPayload(identifiers, json.getString("notBefore"),
        json.getString("notAfter"));
  }

}
