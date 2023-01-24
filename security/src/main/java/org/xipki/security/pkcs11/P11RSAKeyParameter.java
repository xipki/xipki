/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.security.pkcs11;

import org.bouncycastle.crypto.params.RSAKeyParameters;

import static org.xipki.util.Args.notNull;

/**
 * {@link RSAKeyParameters} for PKCS#11 token.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
public class P11RSAKeyParameter extends RSAKeyParameters {

  private final P11Identity identity;

  private final int keysize;

  public P11RSAKeyParameter(P11Identity identity) {
    super(true, identity.getRsaModulus(), identity.getRsaPublicExponent());

    this.identity = notNull(identity, "identity");
    this.keysize = identity.getRsaModulus().bitLength();
  }

  int getKeysize() {
    return keysize;
  }

  P11Identity getIdentity() {
    return identity;
  }

}
