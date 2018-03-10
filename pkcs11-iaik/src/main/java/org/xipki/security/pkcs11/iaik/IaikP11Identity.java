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

package org.xipki.security.pkcs11.iaik;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.xipki.common.util.ParamUtil;
import org.xipki.security.exception.P11TokenException;
import org.xipki.security.pkcs11.P11EntityIdentifier;
import org.xipki.security.pkcs11.P11Identity;
import org.xipki.security.pkcs11.P11Params;

import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.SecretKey;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class IaikP11Identity extends P11Identity {

  private final Key signingKey;

  private final int expectedSignatureLen;

  IaikP11Identity(IaikP11Slot slot, P11EntityIdentifier identityId, SecretKey signingKey) {
    super(slot, identityId, 0);
    this.signingKey = ParamUtil.requireNonNull("signingKey", signingKey);
    this.expectedSignatureLen = 0;
  }

  IaikP11Identity(IaikP11Slot slot, P11EntityIdentifier identityId, PrivateKey privateKey,
      PublicKey publicKey, X509Certificate[] certificateChain) {
    super(slot, identityId, publicKey, certificateChain);
    this.signingKey = ParamUtil.requireNonNull("privateKey", privateKey);

    int keyBitLen = signatureKeyBitLength();
    if (publicKey instanceof RSAPublicKey) {
      expectedSignatureLen = (keyBitLen + 7) / 8;
    } else if (publicKey instanceof ECPublicKey) {
      expectedSignatureLen = (keyBitLen + 7) / 8 * 2;
    } else if (publicKey instanceof DSAPublicKey) {
      expectedSignatureLen = (keyBitLen + 7) / 8 * 2;
    } else {
      throw new IllegalArgumentException("currently only RSA, DSA and EC public key are supported,"
          + " but not " + this.publicKey.getAlgorithm()
          + " (class: " + publicKey.getClass().getName() + ")");
    }
  }

  @Override
  protected byte[] digestSecretKey0(long mechanism) throws P11TokenException {
    if (! (signingKey instanceof SecretKey)) {
      throw new P11TokenException("could not digest asymmetric key");
    }

    Boolean bv = ((SecretKey) signingKey).getExtractable().getBooleanValue();
    if (bv != null && !bv.booleanValue()) {
      throw new P11TokenException("could not digest unextractable key");
    }

    bv = ((SecretKey) signingKey).getNeverExtractable().getBooleanValue();
    if (bv != null && bv.booleanValue()) {
      throw new P11TokenException("could not digest unextractable key");
    }

    return ((IaikP11Slot) slot).digestKey(mechanism, this);
  }

  @Override
  protected byte[] sign0(long mechanism, P11Params parameters, byte[] content)
      throws P11TokenException {
    return ((IaikP11Slot) slot).sign(mechanism, parameters, content, this);
  }

  Key signingKey() {
    return signingKey;
  }

  int expectedSignatureLen() {
    return expectedSignatureLen;
  }

}
