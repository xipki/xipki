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

package org.xipki.qa.security.pkcs11;

import org.xipki.security.SecurityFactory;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class P11ECSignSpeed extends P11SignSpeed {

  public P11ECSignSpeed(SecurityFactory securityFactory, P11Slot slot, byte[] keyId,
      String signatureAlgorithm, int threads, String curveNameOrOid) throws Exception {
    this(false, securityFactory, slot, keyId, null, signatureAlgorithm, threads, curveNameOrOid);
  }

  public P11ECSignSpeed(boolean keyPresent, SecurityFactory securityFactory, P11Slot slot,
      byte[] keyId, String keyLabel, String signatureAlgorithm, int threads, String curveNameOrOid)
          throws Exception {
    super(securityFactory, slot, signatureAlgorithm, !keyPresent,
        generateKey(keyPresent, slot, keyId, keyLabel, curveNameOrOid),
        "PKCS#11 EC signature creation\ncurve: " + curveNameOrOid, threads);
  }

  private static P11ObjectIdentifier generateKey(boolean keyPresent, P11Slot slot, byte[] keyId,
      String keyLabel, String curveNameOrOid) throws Exception {
    if (keyPresent) {
      return getNonNullKeyId(slot, keyId, keyLabel);
    }

    return slot.generateECKeypair(curveNameOrOid, getNewKeyControl(keyId, keyLabel)).getKeyId();
  }

}
