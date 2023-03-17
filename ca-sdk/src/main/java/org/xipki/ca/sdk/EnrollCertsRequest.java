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

public class EnrollCertsRequest extends CertsRequest {

  private List<EnrollCertRequestEntry> entries;

  public List<EnrollCertRequestEntry> getEntries() {
    return entries;
  }

  public void setEntries(List<EnrollCertRequestEntry> entries) {
    this.entries = entries;
  }

  public static EnrollCertsRequest decode(byte[] encoded) {
    return JSON.parseObject(encoded, EnrollCertsRequest.class);
  }

}
