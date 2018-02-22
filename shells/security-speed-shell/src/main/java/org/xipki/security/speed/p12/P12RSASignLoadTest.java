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

package org.xipki.security.speed.p12;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.xipki.security.SecurityFactory;
import org.xipki.security.pkcs12.KeystoreGenerationParameters;
import org.xipki.security.pkcs12.P12KeyGenerationResult;
import org.xipki.security.pkcs12.P12KeyGenerator;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class P12RSASignLoadTest extends P12SignLoadTest {

  public P12RSASignLoadTest(SecurityFactory securityFactory, String signatureAlgorithm,
      int keysize, BigInteger publicExponent) throws Exception {
    super(securityFactory, signatureAlgorithm, generateKeystore(keysize, publicExponent),
        "PKCS#12 RSA signature creation\nkeysize: " + keysize + "\n"
            + "public exponent: " + publicExponent);
  }

  private static byte[] generateKeystore(int keysize, BigInteger publicExponent)
      throws Exception {
    byte[] keystoreBytes = getPrecomputedRSAKeystore(keysize, publicExponent);
    if (keystoreBytes == null) {
      KeystoreGenerationParameters params = new KeystoreGenerationParameters(
          PASSWORD.toCharArray());
      params.setRandom(new SecureRandom());
      P12KeyGenerationResult identity = new P12KeyGenerator().generateRSAKeypair(
          keysize, publicExponent, params, null);
      keystoreBytes = identity.keystore();
    }
    return keystoreBytes;
  }

}
