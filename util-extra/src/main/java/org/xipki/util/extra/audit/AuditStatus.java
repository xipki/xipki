// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.audit;

import org.xipki.util.codec.Args;

/**
 * Audit status.
 *
 * @author Lijun Liao (xipki)
 */

public enum AuditStatus {

  SUCCESSFUL,
  FAILED,
  UNDEFINED;

  AuditStatus() {
  }

  public static AuditStatus forName(final String name) {
    Args.notNull(name, "name");
    for (final AuditStatus v : values()) {
      if (v.name().equals(name)) {
        return v;
      }
    }
    throw new IllegalArgumentException("invalid AuditStatus " + name);
  } // method forName

}
