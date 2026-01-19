// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.msg;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class OrdersResponse implements JsonEncodable {

  private final List<String> orders;

  public OrdersResponse(List<String> orders) {
    this.orders = orders;
  }

  public List<String> getOrders() {
    return orders;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().putStrings("orders", orders);
  }

  public static OrdersResponse parse(JsonMap json) throws CodecException {
    return new OrdersResponse(json.getStringList("orders"));
  }

}
