// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.security.util.JSON;

import java.util.List;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class RevokeCertsRequest extends ChangeCertStatusRequest {

  private List<RevokeCertRequestEntry> entries;

  public List<RevokeCertRequestEntry> getEntries() {
    return entries;
  }

  public void setEntries(List<RevokeCertRequestEntry> entries) {
    this.entries = entries;
  }

  public static RevokeCertsRequest decode(byte[] encoded) {
    return JSON.parseObject(encoded, RevokeCertsRequest.class);
  }

}
