// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.msg;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class FinalizeOrderPayload {

  private String csr;

  public String getCsr() {
    return csr;
  }

  public void setCsr(String csr) {
    this.csr = csr;
  }

}
