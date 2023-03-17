// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.transaction;

/**
 * FailInfo enum.
 *
 * @author Lijun Liao
 */

public enum FailInfo {

  /**
   * Unrecognized or unsupported algorithm identifier.
   */
  badAlg(0),

  /**
   * integrity check failed.
   */
  badMessageCheck(1),

  /**
   * transaction not permitted or supported.
   */
  badRequest(2),

  /**
   * The signingTime attribute from the CMS, authenticatedAttributes was not sufficiently.
   * close to the system time
   */
  badTime(3),

  /**
   * No certificate could be identified matching the provided criteria.
   */
  badCertId(4);

  private final int code;

  FailInfo(int code) {
    this.code = code;
  }

  public int getCode() {
    return code;
  }

  public static FailInfo forValue(int code) {
    for (FailInfo m : values()) {
      if (m.code == code) {
        return m;
      }
    }
    throw new IllegalArgumentException("invalid FailInfo " + code);
  }

}
