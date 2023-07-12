// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.acme.util.AcmeUtils;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class ChallId {

  private final long authzId;

  private final int subId;

  public ChallId(long authzId, int subId) {
    this.authzId = authzId;
    this.subId = subId;
  }

  public long getAuthzId() {
    return authzId;
  }

  public int getSubId() {
    return subId;
  }

  @Override
  public boolean equals(Object other) {
    if (!(other instanceof ChallId)) {
      return false;
    }

    ChallId b = (ChallId) other;
    return authzId == b.authzId && subId == b.subId;
  }

  @Override
  public String toString() {
     return AcmeUtils.toBase64(authzId) + "/" + AcmeUtils.toBase64(subId);
  }

  @Override
  public int hashCode() {
    return Long.hashCode(authzId) * 31 + subId;
  }

}
