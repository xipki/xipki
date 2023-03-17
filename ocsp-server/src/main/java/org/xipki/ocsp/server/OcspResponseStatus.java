// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

/**
 * OCSP response status.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public enum OcspResponseStatus {

  successful(0),
  malformedRequest(1),
  internalError(2),
  tryLater(3),
  sigRequired(5),
  unauthorized(6);

  private final int status;

  OcspResponseStatus(int status) {
    this.status = status;
  }

  public int getStatus() {
    return status;
  }

  public static OcspResponseStatus forValue(int status) {
    for (OcspResponseStatus entry : values()) {
      if (entry.status == status) {
        return entry;
      }
    }

    throw new IllegalArgumentException("invalid OcspResponseStatus " + status);
  }

}
