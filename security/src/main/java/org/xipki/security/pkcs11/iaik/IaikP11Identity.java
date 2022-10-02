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

package org.xipki.security.pkcs11.iaik;

import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.SecretKey;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.xipki.security.EdECConstants;
import org.xipki.security.X509Cert;
import org.xipki.security.pkcs11.P11Identity;
import org.xipki.security.pkcs11.P11IdentityId;
import org.xipki.security.pkcs11.P11Params;
import org.xipki.security.pkcs11.P11TokenException;

import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import static org.xipki.util.Args.notNull;

/**
 * {@link P11Identity} based on the IAIK PKCS#11 wrapper.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class IaikP11Identity extends P11Identity {

  private final Key signingKey;

  private final int expectedSignatureLen;

  IaikP11Identity(IaikP11Slot slot, P11IdentityId identityId, SecretKey signingKey) {
    super(slot, identityId, 0);
    this.signingKey = notNull(signingKey, "signingKey");
    this.expectedSignatureLen = 0;
  }

  IaikP11Identity(IaikP11Slot slot, P11IdentityId identityId, PrivateKey privateKey,
                  PublicKey publicKey, X509Cert[] certificateChain) {
    super(slot, identityId, publicKey, certificateChain);
    this.signingKey = notNull(privateKey, "privateKey");

    int keyBitLen = getSignatureKeyBitLength();
    if (publicKey instanceof RSAPublicKey) {
      expectedSignatureLen = (keyBitLen + 7) / 8;
    } else if (publicKey instanceof ECPublicKey) {
      expectedSignatureLen = (keyBitLen + 7) / 8 * 2;
    } else if (publicKey instanceof DSAPublicKey) {
      expectedSignatureLen = (keyBitLen + 7) / 8 * 2;
    } else if (publicKey instanceof EdDSAKey) {
      String algName = publicKey.getAlgorithm();
      if (EdECConstants.ED25519.equalsIgnoreCase(algName)) {
        expectedSignatureLen = 64;
      } else if (EdECConstants.ED448.equalsIgnoreCase(algName)) {
        expectedSignatureLen = 114;
      } else {
        throw new IllegalArgumentException("unknown EdDSA algorithm " + algName);
      }
    } else if (publicKey instanceof XDHKey) {
      // no signature is supported
      expectedSignatureLen = 0;
    } else {
      throw new IllegalArgumentException(
          "currently only RSA, DSA, EC, EdDSA and XDH public key are supported, but not "
          + this.publicKey.getAlgorithm() + " (class: " + publicKey.getClass().getName() + ")");
    }
  } // constructor

  @Override
  protected byte[] digestSecretKey0(long mechanism) throws P11TokenException {
    if (! (signingKey instanceof SecretKey)) {
      throw new P11TokenException("could not digest asymmetric key");
    }

    Boolean bv = ((SecretKey) signingKey).getExtractable().getBooleanValue();
    if (bv != null && !bv) {
      throw new P11TokenException("could not digest unextractable key");
    }

    bv = ((SecretKey) signingKey).getNeverExtractable().getBooleanValue();
    if (bv != null && bv) {
      throw new P11TokenException("could not digest unextractable key");
    }

    return ((IaikP11Slot) slot).digestSecretKey(mechanism, this);
  } // constructor

  @Override
  protected byte[] sign0(long mechanism, P11Params parameters, byte[] content) throws P11TokenException {
    return ((IaikP11Slot) slot).sign(mechanism, parameters, content, this);
  }

  Key getSigningKey() {
    return signingKey;
  }

  int getExpectedSignatureLen() {
    return expectedSignatureLen;
  }

}
