// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.audit;

import org.xipki.util.Args;

/**
 * Audit status.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
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
