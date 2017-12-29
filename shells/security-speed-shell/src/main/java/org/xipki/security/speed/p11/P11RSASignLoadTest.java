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

import java.math.BigInteger;

import org.xipki.common.util.ParamUtil;
import org.xipki.security.SecurityFactory;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class P11RSASignLoadTest extends P11SignLoadTest {

    public P11RSASignLoadTest(SecurityFactory securityFactory, P11Slot slot,
            String signatureAlgorithm, int keysize, BigInteger publicExponent) throws Exception {
        super(securityFactory, slot, signatureAlgorithm,
                generateKey(slot, keysize, publicExponent),
                "PKCS#11 RSA signature creation\n"
                        + "keysize: " + keysize + "\n"
                        + "public exponent: " + publicExponent);
    }

    private static P11ObjectIdentifier generateKey(P11Slot slot, int keysize,
            BigInteger publicExponent) throws Exception {
        ParamUtil.requireNonNull("slot", slot);
        return slot.generateRSAKeypair(keysize, publicExponent,
                "loadtest-" + System.currentTimeMillis(), getNewKeyControl());
    }

}
