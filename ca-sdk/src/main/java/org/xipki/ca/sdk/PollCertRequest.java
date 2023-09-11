// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class PollCertRequest extends CaIdentifierRequest {

  private String transactionId;

  private List<PollCertRequestEntry> entries;

  public String getTransactionId() {
    return transactionId;
  }

  public void setTransactionId(String transactionId) {
    this.transactionId = transactionId;
  }

  public List<PollCertRequestEntry> getEntries() {
    return entries;
  }

  public void setEntries(List<PollCertRequestEntry> entries) {
    this.entries = entries;
  }

  public static PollCertRequest decode(byte[] encoded) {
    return CBOR.parseObject(encoded, PollCertRequest.class);
  }

}
