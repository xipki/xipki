// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.type;

import org.xipki.ca.gateway.acme.AcmeIdentifier;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class Identifier implements JsonEncodable {

  private final String type;

  private final String value;

  public Identifier(String type, String value) {
    this.type = type;
    this.value = value;
  }

  public String getType() {
    return type;
  }

  public String getValue() {
    return value;
  }

  public AcmeIdentifier toAcmeIdentifier() {
    return new AcmeIdentifier(type, value);
  }

  public String toString() {
    return type + "/" + value;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("type", type).put("value", value);
  }

  public static Identifier parse(JsonMap json) throws CodecException {
    return new Identifier(json.getString("type"), json.getString("value"));
  }
}
