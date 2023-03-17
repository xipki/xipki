// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.api.mgmt;

/**
 * OCSP server management request.
 *
 * @author Lijun Liao (xipki)
 */

public abstract class MgmtRequest extends MgmtMessage {

  public static class Name extends MgmtRequest {

    private String name;

    public Name() {
    }

    public Name(String name) {
      this.name = name;
    }

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

  }

}
