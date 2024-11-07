// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.transaction;

/**
 * PKI status enum.
 *
 * @author Lijun Liao (xipki)
 */

public enum PkiStatus {

  /**
   * request granted.
   */
  SUCCESS(0),

  /**
   * request rejected.
   */
  FAILURE(2),

  /**
   * request pending for manual approval.
   */
  PENDING(3);

  private final int code;

  PkiStatus(int code) {
    this.code = code;
  }

  public int getCode() {
    return code;
  }

  public static PkiStatus forValue(int code) {
    for (PkiStatus m : values()) {
      if (m.code == code) {
        return m;
      }
    }
    throw new IllegalArgumentException("invalid PkiStatus " + code);
  }

}
