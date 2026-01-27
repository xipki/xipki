// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.msg;

import org.xipki.ca.gateway.acme.type.Identifier;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class Subproblem implements JsonEncodable {

  private final String type;

  private final String detail;

  private final Identifier identifier;

  public Subproblem(String type, String detail, Identifier identifier) {
    this.type = type;
    this.detail = detail;
    this.identifier = identifier;
  }

  public String getType() {
    return type;
  }

  public Identifier getIdentifier() {
    return identifier;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("type", type)
        .put("detail", detail).put("identifier", identifier);
  }

  public static Subproblem parse(JsonMap json) throws CodecException {
    JsonMap map = json.getMap("identifier");
    Identifier identifier = (map == null) ? null : Identifier.parse(map);
    return new Subproblem(json.getString("type"),
        json.getString("detail"), identifier);
  }

}
