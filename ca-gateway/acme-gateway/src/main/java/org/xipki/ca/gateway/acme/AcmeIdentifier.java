// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.type.Identifier;
import org.xipki.util.Args;
import org.xipki.util.CompareUtil;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeIdentifier {

  private String type;

  private String value;

  private AcmeIdentifier() {
  }

  public AcmeIdentifier(String type, String value) {
    this.type = Args.notNull(type, "type");
    this.value = Args.notNull(value, "value");
  }

  public void setType(String type) {
    this.type = type;
  }

  public void setValue(String value) {
    this.value = value;
  }

  public String getType() {
    return type;
  }

  public String getValue() {
    return value;
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
