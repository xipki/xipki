// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.bouncycastle.util.Pack;
import org.xipki.util.Args;
import org.xipki.util.Base64Url;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AuthzId {

  private final long orderId;

  private final int subId;

  private final String idText;

  public AuthzId(long orderId, int subId) {
    this.orderId = orderId;
    this.subId = Args.range(subId, "subId", 0, 0xFFFF);

    byte[] orderIdBytes = Pack.longToBigEndian(orderId);
    byte[] encoded = new byte[10];

    // reverse the bytes
    encoded[0] = (byte) subId;
    encoded[1] = (byte) (subId >> 8);

    for (int i = 0; i < 8; i++) {
      encoded[2 + i] = orderIdBytes[7 - i];
    }
    this.idText = Base64Url.encodeToStringNoPadding(encoded);
  }

  public AuthzId(byte[] encoded) {
    if (encoded.length != 10) {
      throw new IllegalArgumentException("invalid encoded.length");
    }

    this.subId   = (encoded[0] & 0xFF) + ((encoded[1] & 0xFF) << 8);
    this.orderId = Pack.littleEndianToLong(encoded, 2);
    this.idText = Base64Url.encodeToStringNoPadding(encoded);
  }

  public long getOrderId() {
    return orderId;
  }

  public int getSubId() {
    return subId;
  }

  @Override
  public String toString() {
    return idText;
  }

  @Override
  public boolean equals(Object other) {
    if (!(other instanceof AuthzId)) {
      return false;
    }

    AuthzId b = (AuthzId) other;
    return orderId == b.orderId && subId == b.subId;
  }

  public String toIdText() {
    return idText;
  }

}
