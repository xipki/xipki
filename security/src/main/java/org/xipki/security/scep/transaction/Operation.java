// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.scep.transaction;

/**
 * Operation enum.
 *
 * @author Lijun Liao (xipki)
 */

public enum Operation {

  GetCACaps("GetCACaps"),
  PKIOperation("PKIOperation"),
  GetCACert("GetCACert"),
  GetNextCACert("GetNextCACert");

  private final String code;

  Operation(String code) {
    this.code = code;
  }

  public String code() {
    return code;
  }

}
