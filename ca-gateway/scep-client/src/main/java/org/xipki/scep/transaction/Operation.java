// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.transaction;

import org.xipki.util.Args;

/**
 * Operation enum.
 *
 * @author Lijun Liao
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

  public String getCode() {
    return code;
  }

  public static Operation forValue(String code) {
    Args.notBlank(code, "code");
    for (Operation m : values()) {
      if (code.equalsIgnoreCase(m.code)) {
        return m;
      }
    }
    throw new IllegalArgumentException("invalid Operation " + code);
  }

}
