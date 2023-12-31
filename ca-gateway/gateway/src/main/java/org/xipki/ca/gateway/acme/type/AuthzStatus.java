// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.type;

/**
 *
 * @author Lijun Liao (xipki)
 */
public enum AuthzStatus {

  valid(1),
  pending(2),
  deactivated(10),
  expired(11),
  invalid(12),
  revoked(13);

  private final int code;

  AuthzStatus(int code) {
    this.code = code;
  }

  public int getCode() {
    return code;
  }

  public static AuthzStatus ofCode(int code) {
    for (AuthzStatus status : values()) {
      if (status.code == code) {
        return status;
      }
    }
    return null;
  }

}
