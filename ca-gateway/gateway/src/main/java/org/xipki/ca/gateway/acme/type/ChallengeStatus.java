// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.type;

/**
 *
 * @author Lijun Liao (xipki)
 */
public enum ChallengeStatus {

  valid(1),
  pending(2),
  processing(3),
  invalid(12);

  private final int code;

  ChallengeStatus(int code) {
    this.code = code;
  }

  public int getCode() {
    return code;
  }

  public static ChallengeStatus ofCode(int code) {
    for (ChallengeStatus status : values()) {
      if (status.code == code) {
        return status;
      }
    }
    return null;
  }

}
