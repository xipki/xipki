// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ocsp;

import org.xipki.util.Args;

/**
 * OCSP error enum.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public enum OcspError {

  malformedRequest(1),
  internalError(2),
  tryLater(3),
  sigRequired(4),
  unauthorized(5);

  private final int status;

  OcspError(int status) {
    this.status = status;
  }

  public int getStatus() {
    return status;
  }

  public static OcspError forName(String name) {
    Args.notNull(name, "name");
    for (OcspError entry : values()) {
      if (entry.name().equals(name)) {
        return entry;
      }
    }

    throw new IllegalArgumentException("unknown OCSP error '" + name + "'");
  }

  public static OcspError forCode(int status) {
    for (OcspError entry : values()) {
      if (entry.status == status) {
        return entry;
      }
    }

    throw new IllegalArgumentException("unknown OCSP error code '" + status + "'");
  }

}
