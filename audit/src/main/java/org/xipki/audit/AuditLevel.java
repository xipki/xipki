// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.audit;

import org.xipki.util.Args;

/**
 * Audit level.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public enum AuditLevel {

  ERROR(3, "ERROR"),
  WARN(4,  "WARN"),
  INFO(6,  "INFO");

  private final int value;

  private final String text;

  AuditLevel(int value, String text) {
    this.value = value;
    this.text = text;
  }

  public int getValue() {
    return value;
  }

  public static AuditLevel forName(String name) {
    Args.notNull(name, "name");
    for (AuditLevel value : values()) {
      if (value.name().equals(name)) {
        return value;
      }
    }
    throw new IllegalArgumentException("invalid AuditLevel name " + name);
  }

  public static AuditLevel forValue(int value) {
    for (AuditLevel v : values()) {
      if (v.getValue() == value) {
        return v;
      }
    }
    throw new IllegalArgumentException("invalid AuditLevel code " + value);
  }

  public String getText() {
    return text;
  }

}
