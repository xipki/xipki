// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.type.Identifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.json.JsonEncodable;
import org.xipki.codec.json.JsonMap;
import org.xipki.pkix.util.misc.CompareUtil;

/**
 * ACME Identifier.
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeIdentifier implements JsonEncodable {

  private final String type;

  private final String value;

  public AcmeIdentifier(String type, String value) {
    this.type = Args.notNull(type, "type");
    this.value = Args.notNull(value, "value");
  }

  public String type() {
    return type;
  }

  public String value() {
    return value;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("type", type).put("value", value);
  }

  public static AcmeIdentifier parse(JsonMap json) throws CodecException {
    return new AcmeIdentifier(json.getNnString("type"), json.getNnString("value"));
  }

  @Override
  public boolean equals(Object other) {
    if (!(other instanceof AcmeIdentifier)) {
      return false;
    }

    AcmeIdentifier b = (AcmeIdentifier) other;
    return CompareUtil.equals(type, b.type) && CompareUtil.equals(value, b.value);
  }

  public Identifier toIdentifier() {
    return new Identifier(type, value);
  }

}
