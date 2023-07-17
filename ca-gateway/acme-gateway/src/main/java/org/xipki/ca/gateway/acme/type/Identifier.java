// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.type;

import org.xipki.ca.gateway.acme.AcmeIdentifier;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class Identifier {

  private String type;

  private String value;

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public String getValue() {
    return value;
  }

  public void setValue(String value) {
    this.value = value;
  }

  public AcmeIdentifier toAcmeIdentifier() {
    return new AcmeIdentifier(type, value);
  }

  public String toString() {
    return type + "/" + value;
  }

}
