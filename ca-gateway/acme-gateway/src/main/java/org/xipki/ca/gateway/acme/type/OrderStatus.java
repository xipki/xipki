// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.type;

/**
 *
 * @author Lijun Liao (xipki)
 */
public enum OrderStatus {

  valid(1),
  pending(2),
  processing(3),
  ready(4),
  invalid(12);

  private final int code;

  OrderStatus(int code) {
    this.code = code;
  }

  public int getCode() {
    return code;
  }

  public static OrderStatus ofCode(int code) {
    for (OrderStatus status : values()) {
      if (status.code == code) {
        return status;
      }
    }
    return null;
  }

}
