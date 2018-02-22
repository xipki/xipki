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

package org.xipki.security.speed.p11;

import java.security.SecureRandom;

import org.xipki.common.util.ParamUtil;
import org.xipki.security.SecurityFactory;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.speed.p12.P12HMACSignLoadTest;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */
// CHECKSTYLE:SKIP
public class P11HMACSignLoadTest extends P11SignLoadTest {

  public P11HMACSignLoadTest(SecurityFactory securityFactory, P11Slot slot,
      String signatureAlgorithm) throws Exception {
    super(securityFactory, slot, signatureAlgorithm,
        generateKey(slot, signatureAlgorithm), "PKCS#11 HMAC signature creation");
  }

  private static P11ObjectIdentifier generateKey(P11Slot slot, String signatureAlgorithm)
      throws Exception {
    ParamUtil.requireNonNull("slot", slot);
    int keysize = P12HMACSignLoadTest.getKeysize(signatureAlgorithm);
    byte[] keyBytes = new byte[keysize / 8];
    new SecureRandom().nextBytes(keyBytes);
    return slot.importSecretKey(PKCS11Constants.CKK_GENERIC_SECRET, keyBytes,
        "loadtest-" + System.currentTimeMillis(), getNewKeyControl());
  }

}
