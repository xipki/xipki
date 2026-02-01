// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.msg;

import org.xipki.ca.gateway.acme.type.Identifier;
import org.xipki.ca.gateway.acme.type.OrderStatus;
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
public class OrderResponse implements JsonEncodable {

  private final OrderStatus status;
  private final String expires;
  private final String notBefore;
  private final String notAfter;
  private final List<Identifier> identifiers;
  private final List<String> authorizations;
  private final String finalize;
  private final String certificate;

  public OrderResponse(
      OrderStatus status, String expires, String notBefore,
      String notAfter, List<Identifier> identifiers,
      List<String> authorizations, String finalize, String certificate) {
    this.status = status;
    this.expires = expires;
    this.notBefore = notBefore;
    this.notAfter = notAfter;
    this.identifiers = identifiers;
    this.authorizations = authorizations;
    this.finalize = finalize;
    this.certificate = certificate;
  }

  public OrderStatus status() {
    return status;
  }

  public String expires() {
    return expires;
  }

  public String notBefore() {
    return notBefore;
  }

  public String notAfter() {
    return notAfter;
  }

  public List<Identifier> identifiers() {
    return identifiers;
  }

  public List<String> authorizations() {
    return authorizations;
  }

  public String getFinalize() {
    return finalize;
  }

  public String certificate() {
    return certificate;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().putEnum("status", status).put("expires", expires)
        .put("notBefore", notBefore).put("notAfter", notAfter)
        .putEncodables("identifiers", identifiers)
        .putStrings("authorizations", authorizations)
        .put("finalize", finalize).put("certificate", certificate);
  }

  public static OrderResponse parse(JsonMap json) throws CodecException {
    OrderStatus status = json.getEnum("status", OrderStatus.class);

    JsonList list = json.getList("identifiers");
    List<Identifier> identifiers = null;
    if (list != null) {
      identifiers = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        identifiers.add(Identifier.parse(v));
      }
    }

    return new OrderResponse(status, json.getString("expires"),
        json.getString("notBefore"), json.getString("notAfter"),
        identifiers, json.getStringList("authorizations"),
        json.getString("finalize"), json.getString("certificate"));
  }
}
