// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.security.util.JSON;

import java.math.BigInteger;
import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class UnsuspendOrRemoveRequest extends CaIdentifierRequest {

  private List<BigInteger> entries;

  public List<BigInteger> getEntries() {
    return entries;
  }

  public void setEntries(List<BigInteger> entries) {
    this.entries = entries;
  }

  public static UnsuspendOrRemoveRequest decode(byte[] encoded) {
    return JSON.parseObject(encoded, UnsuspendOrRemoveRequest.class);
  }

}
