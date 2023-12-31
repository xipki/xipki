// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.msg;

import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class OrdersResponse {

  private List<String> orders;

  public List<String> getOrders() {
    return orders;
  }

  public void setOrders(List<String> orders) {
    this.orders = orders;
  }

}
