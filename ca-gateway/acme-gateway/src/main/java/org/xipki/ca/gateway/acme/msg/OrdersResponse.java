// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.msg;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class OrdersResponse {

  private String[] orders;

  public String[] getOrders() {
    return orders;
  }

  public void setOrders(String[] orders) {
    this.orders = orders;
  }

}
