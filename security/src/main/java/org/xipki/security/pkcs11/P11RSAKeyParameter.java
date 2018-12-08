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

package org.xipki.security.pkcs11;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class P11RSAKeyParameter extends RSAKeyParameters {

  private final P11CryptService p11CryptService;

  private final P11IdentityId identityId;

  private final int keysize;

  private P11RSAKeyParameter(P11CryptService p11CryptService, P11IdentityId identityId,
      BigInteger modulus, BigInteger publicExponent) {
    super(true, modulus, publicExponent);

    Args.notNull(modulus,"modulus");
    Args.notNull(publicExponent, "publicExponent");
    this.p11CryptService = Args.notNull(p11CryptService, "p11CryptService");
    this.identityId = Args.notNull(identityId, "identityId");
    this.keysize = modulus.bitLength();
  }

  int getKeysize() {
    return keysize;
  }

  P11CryptService getP11CryptService() {
    return p11CryptService;
  }

  P11IdentityId getIdentityId() {
    return identityId;
  }

  public static P11RSAKeyParameter getInstance(P11CryptService p11CryptService,
      P11IdentityId identityId) throws InvalidKeyException {
    Args.notNull(p11CryptService, "p11CryptService");
    Args.notNull(identityId, "identityId");

    RSAPublicKey key;
    try {
      key = (RSAPublicKey) p11CryptService.getIdentity(identityId).getPublicKey();
    } catch (P11TokenException ex) {
      throw new InvalidKeyException(ex.getMessage(), ex);
    }

    BigInteger modulus = key.getModulus();
    BigInteger publicExponent = key.getPublicExponent();
    return new P11RSAKeyParameter(p11CryptService, identityId, modulus, publicExponent);
  }

}
