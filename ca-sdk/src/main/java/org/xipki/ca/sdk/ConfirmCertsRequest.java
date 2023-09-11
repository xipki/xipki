// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.security.util.CBOR;

import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class ConfirmCertsRequest extends SdkRequest {

  private String transactionId;

  private List<ConfirmCertRequestEntry> entries;

  public String getTransactionId() {
    return transactionId;
  }

  public void setTransactionId(String transactionId) {
    this.transactionId = transactionId;
  }

  public List<ConfirmCertRequestEntry> getEntries() {
    return entries;
  }

  public void setEntries(List<ConfirmCertRequestEntry> entries) {
    this.entries = entries;
  }

  public static ConfirmCertsRequest decode(byte[] encoded) {
    return CBOR.parseObject(encoded, ConfirmCertsRequest.class);
  }

}
