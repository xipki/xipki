// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.util.codec.Args;

/**
 * CA status enum.
 *
 * @author Lijun Liao (xipki)
 */

public enum CaStatus {

  active("active"),
  inactive("inactive");

  private final String status;

  CaStatus(String status) {
    this.status = status;
  }

  public String status() {
    return status;
  }

  public static CaStatus forName(String status) {
    Args.notNull(status, "status");
    for (CaStatus value : values()) {
      if (value.status.equalsIgnoreCase(status)) {
        return value;
      }
    }

    throw new IllegalArgumentException("invalid CaStatus " + status);
  }

}
