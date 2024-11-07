// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.transaction;

import org.xipki.util.Args;

/**
 * CA capability enum.
 *
 * @author Lijun Liao (xipki)
 */

public enum CaCapability {

  AES("AES"),
  DES3("DES3"),
  GetNextCACert("GetNextCACert"),
  POSTPKIOperation("POSTPKIOperation"),
  Renewal("Renewal"),
  SHA1("SHA-1"),
  SHA256("SHA-256"),
  SHA512("SHA-512"),
  // SCEPStandard: AES, SHA-256, POSTPKIOperation, GetCACaps, GetCACert, PKCSReq
  SCEPStandard("SCEPStandard");

  private final String text;

  CaCapability(String text) {
    this.text = text;
  }

  public String getText() {
    return text;
  }

  public static CaCapability forValue(String text) {
    Args.notNull(text, "text");
    for (CaCapability m : values()) {
      if (m.text.equalsIgnoreCase(text)) {
        return m;
      }
    }
    throw new IllegalArgumentException("invalid CaCapability " + text);
  }

}
