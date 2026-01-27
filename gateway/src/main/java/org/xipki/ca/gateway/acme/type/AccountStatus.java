// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.type;

/**
 *
 * @author Lijun Liao (xipki)
 */
public enum AccountStatus {

  valid(1),
  deactivated (10),
  revoked (13);

  private final int code;

  AccountStatus(int code) {
    this.code = code;
  }

  public int getCode() {
    return code;
  }

  public static AccountStatus ofCode(int code) {
    for (AccountStatus status : values()) {
      if (status.code == code) {
        return status;
      }
    }
    return null;
  }

}
