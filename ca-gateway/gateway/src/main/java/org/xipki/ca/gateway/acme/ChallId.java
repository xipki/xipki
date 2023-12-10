// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.bouncycastle.util.Pack;
import org.xipki.util.Args;
import org.xipki.util.Base64Url;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class ChallId {

  private final long orderId;

  private final int authzId;

  private final int subId;

  private final String idText;

  public ChallId(long orderId, int authzId, int subId) {
    this.orderId = orderId;
    this.authzId = Args.range(authzId, "authzId", 0, 0xFFFF);
    this.subId = Args.range(subId, "subId", 0, 0xFFFF);

    byte[] orderIdBytes = Pack.longToBigEndian(orderId);
    byte[] encoded = new byte[12];
    // reverse the bytes
    encoded[0] = (byte) subId;
    encoded[1] = (byte) (subId >> 8);

    encoded[2] = (byte) authzId;
    encoded[3] = (byte) (authzId >> 8);

    for (int i = 0; i < 8; i++) {
      encoded[4 + i] = orderIdBytes[7 - i];
    }
    this.idText = Base64Url.encodeToStringNoPadding(encoded);
  }

  public ChallId(byte[] encoded) {
    if (encoded.length != 12) {
      throw new IllegalArgumentException("invalid encoded.length");
    }

    this.subId   = (encoded[0] & 0xFF) + ((encoded[1] & 0xFF) << 8);
    this.authzId = (encoded[2] & 0xFF) + ((encoded[3] & 0xFF) << 8);
    this.orderId = Pack.littleEndianToLong(encoded, 4);
    this.idText = Base64Url.encodeToStringNoPadding(encoded);
  }

  public long getOrderId() {
    return orderId;
  }

  public int getAuthzId() {
    return authzId;
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
    if (!(other instanceof ChallId)) {
      return false;
    }

    ChallId b = (ChallId) other;
    return orderId == b.orderId && authzId == b.authzId && subId == b.subId;
  }

  public String toIdText() {
    return idText;
  }

}
