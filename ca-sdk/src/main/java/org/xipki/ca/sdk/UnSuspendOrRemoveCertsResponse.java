// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import java.util.List;

/**
 * Response for the operations unrevoking certificates and removing certificates.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class UnSuspendOrRemoveCertsResponse extends SdkResponse {

  private List<SingleCertSerialEntry> entries;

  public List<SingleCertSerialEntry> getEntries() {
    return entries;
  }

  public void setEntries(List<SingleCertSerialEntry> entries) {
    this.entries = entries;
  }

  public static UnSuspendOrRemoveCertsResponse decode(byte[] encoded) {
    return CBOR.parseObject(encoded, UnSuspendOrRemoveCertsResponse.class);
  }

}
