// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.security.util.JSON;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class TransactionIdRequest extends SdkRequest {

  private String tid;

  public String getTid() {
    return tid;
  }

  public void setTid(String tid) {
    this.tid = tid;
  }

  public static TransactionIdRequest decode(byte[] encoded) {
    return JSON.parseObject(encoded, TransactionIdRequest.class);
  }

}
