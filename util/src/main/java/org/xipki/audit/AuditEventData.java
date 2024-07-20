// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.audit;

import org.xipki.util.Args;

/**
 * Audit event data.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class AuditEventData {

  private final String name;

  private String value;

  public AuditEventData(String name, Object value) {
    this.name = Args.notBlank(name, "name");
    if (value == null) {
      this.value = "null";
    } else {
      this.value = (value instanceof String) ? (String) value : value.toString();
    }
  } // constructor

  public void addValue(Object additionalValue) {
    this.value += "," + additionalValue;
  }

  public String getName() {
    return name;
  }

  public String getValue() {
    return value;
  }

  @Override
  public String toString() {
    return name + ": " + value;
  }
}
