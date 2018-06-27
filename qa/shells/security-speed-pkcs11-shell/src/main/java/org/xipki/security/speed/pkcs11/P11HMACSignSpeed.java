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

package org.xipki.security.speed.pkcs11;

import java.security.SecureRandom;

import org.xipki.security.SecurityFactory;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;

import iaik.pkcs.pkcs11.constants.PKCS11Constants;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */
// CHECKSTYLE:SKIP
public class P11HMACSignSpeed extends P11SignSpeed {

  public P11HMACSignSpeed(SecurityFactory securityFactory, P11Slot slot, byte[] keyId,
      String signatureAlgorithm) throws Exception {
    this(!false, securityFactory, slot, keyId, null, signatureAlgorithm);
  }

  public P11HMACSignSpeed(boolean keyPresent, SecurityFactory securityFactory, P11Slot slot,
      byte[] keyId, String keyLabel, String signatureAlgorithm) throws Exception {
    super(securityFactory, slot, signatureAlgorithm, !keyPresent,
        generateKey(keyPresent, slot, keyId, keyLabel, signatureAlgorithm),
        "PKCS#11 HMAC signature creation");
  }

  private static P11ObjectIdentifier generateKey(boolean keyPresent, P11Slot slot,
      byte[] keyId, String keyLabel, String signatureAlgorithm) throws Exception {
    if (keyPresent) {
      return getNonNullKeyId(slot, keyId, keyLabel);
    }

    int keysize = getKeysize(signatureAlgorithm);
    byte[] keyBytes = new byte[keysize / 8];
    new SecureRandom().nextBytes(keyBytes);
    return slot.importSecretKey(PKCS11Constants.CKK_GENERIC_SECRET, keyBytes,
        getNewKeyControl(keyId, keyLabel));
  }

  private static int getKeysize(String hmacAlgorithm) {
    int keysize;
    if ("HMACSHA1".equalsIgnoreCase(hmacAlgorithm)) {
      keysize = 160;
    } else if ("HMACSHA224".equalsIgnoreCase(hmacAlgorithm)
        || "HMACSHA3-224".equalsIgnoreCase(hmacAlgorithm)) {
      keysize = 224;
    } else if ("HMACSHA256".equalsIgnoreCase(hmacAlgorithm)
        || "HMACSHA3-256".equalsIgnoreCase(hmacAlgorithm)) {
      keysize = 256;
    } else if ("HMACSHA384".equalsIgnoreCase(hmacAlgorithm)
        || "HMACSHA3-384".equalsIgnoreCase(hmacAlgorithm)) {
      keysize = 384;
    } else if ("HMACSHA512".equalsIgnoreCase(hmacAlgorithm)
        || "HMACSHA3-512".equalsIgnoreCase(hmacAlgorithm)) {
      keysize = 512;
    } else {
      throw new IllegalArgumentException("unknown HMAC algorithm " + hmacAlgorithm);
    }
    return keysize;
  }

}
