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

package org.xipki.security.speed.pkcs12;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.xipki.security.SecurityFactory;
import org.xipki.security.util.KeyUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class P12RSAKeyGenLoadTest extends P12KeyGenLoadTest {

  private final int keysize;
  private final BigInteger publicExponent;

  public P12RSAKeyGenLoadTest(int keysize, BigInteger publicExponent,
      SecurityFactory securityFactory) throws Exception {
    super("PKCS#12 RSA key generation\nkeysize: " + keysize + "\n"
        + "public exponent: " + publicExponent, securityFactory);

    this.keysize = keysize;
    this.publicExponent = publicExponent;
  }

  @Override
  protected void generateKeypair(SecureRandom random) throws Exception {
    KeyUtil.generateRSAKeypair(keysize, publicExponent, random);
  }

}
