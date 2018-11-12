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

package org.xipki.qa.security.benchmark.pkcs11;

import org.xipki.security.SecurityFactory;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class P11DSASignSpeed extends P11SignSpeed {

  public P11DSASignSpeed(SecurityFactory securityFactory, P11Slot slot, byte[] keyId,
      String signatureAlgorithm, int threads, int plength, int qlength) throws Exception {
    this(false, securityFactory, slot, keyId, null, signatureAlgorithm, threads, plength, qlength);
  }

  public P11DSASignSpeed(boolean keyPresent, SecurityFactory securityFactory, P11Slot slot,
      byte[] keyId, String keyLabel, String signatureAlgorithm, int threads,
      int plength, int qlength) throws Exception {
    super(securityFactory, slot, signatureAlgorithm, !keyPresent,
        generateKey(keyPresent, slot, keyId, keyLabel, plength, qlength),
        "PKCS#11 DSA signature creation\npLength: " + plength + "\nqLength: " + qlength, threads);
  }

  private static P11ObjectIdentifier generateKey(boolean keyPresent, P11Slot slot, byte[] keyId,
      String keyLabel, int plength, int qlength) throws Exception {
    if (keyPresent) {
      return getNonNullKeyId(slot, keyId, keyLabel);
    }

    return slot.generateDSAKeypair(plength, qlength, getNewKeyControl(keyId, keyLabel)).getKeyId();
  }

}
