// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.type.Identifier;
import org.xipki.util.Args;
import org.xipki.util.CompareUtil;

import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeIdentifier {

  private final String type;

  private final String value;

  public AcmeIdentifier(String type, String value) {
    this.type = Args.notNull(type, "type");
    this.value = Args.notNull(value, "value");
  }

  public String getType() {
    return type;
  }

  public String getValue() {
    return value;
  }

  public Map<String, String> encode() {
    Map<String, String> map = new HashMap<>();
    map.put("type", type);
    map.put("value", value);
    return map;
  }

  public static AcmeIdentifier decode(Map<String, Object> encoded) {
    return new AcmeIdentifier(
        (String) encoded.get("type"), (String) encoded.get("value"));
  }

  public boolean equals(Object other) {
    if (!(other instanceof AcmeIdentifier)) {
      return false;
    }

    AcmeIdentifier b = (AcmeIdentifier) other;
    return CompareUtil.equalsObject(type, b.type) && CompareUtil.equalsObject(value, b.value);
  }

  public Identifier toIdentifier() {
    Identifier identifier = new Identifier();
    identifier.setType(type);
    identifier.setValue(value);
    return identifier;
  }

}
