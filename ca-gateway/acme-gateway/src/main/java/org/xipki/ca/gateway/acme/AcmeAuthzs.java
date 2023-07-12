// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeAuthzs {

  private List<AcmeAuthz> authzs;

  public List<AcmeAuthz> getAuthzs() {
    return authzs;
  }

  public void setAuthzs(List<AcmeAuthz> authzs) {
    this.authzs = authzs;
  }

}
