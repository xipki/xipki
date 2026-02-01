// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.audit;

import org.xipki.util.codec.Args;

/**
 * Audit level.
 *
 * @author Lijun Liao (xipki)
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

  public int value() {
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
      if (v.value() == value) {
        return v;
      }
    }
    throw new IllegalArgumentException("invalid AuditLevel code " + value);
  }

  public String text() {
    return text;
  }

}
