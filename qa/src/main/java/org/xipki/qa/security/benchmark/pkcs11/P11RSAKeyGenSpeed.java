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

import java.math.BigInteger;

import org.xipki.security.pkcs11.P11IdentityId;
import org.xipki.security.pkcs11.P11Slot;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class P11RSAKeyGenSpeed extends P11KeyGenSpeed {

  private final int keysize;

  private final BigInteger publicExponent;

  public P11RSAKeyGenSpeed(P11Slot slot, byte[] id, int keysize, BigInteger publicExponent)
      throws Exception {
    super(slot, id, "PKCS#11 RSA key generation\nkeysize: " + keysize
        + "\npublic exponent: " + publicExponent);
    this.keysize = keysize;
    this.publicExponent = publicExponent;
  }

  @Override
  protected void genKeypair() throws Exception {
    P11IdentityId objId = slot.generateRSAKeypair(keysize, publicExponent, getControl());
    slot.removeIdentity(objId);
  }

}
