/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.scep.transaction;

import org.xipki.scep.util.ScepUtil;

/**
 * TODO.
 * @author Lijun Liao
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
  Update("Update");

  private String text;

  CaCapability(String text) {
    this.text = text;
  }

  public String getText() {
    return text;
  }

  public static CaCapability forValue(String text) {
    ScepUtil.requireNonNull("text", text);
    for (CaCapability m : values()) {
      if (m.text.equalsIgnoreCase(text)) {
        return m;
      }
    }
    throw new IllegalArgumentException("invalid CaCapability " + text);
  }

}
