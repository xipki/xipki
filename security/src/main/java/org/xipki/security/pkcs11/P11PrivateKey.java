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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.pkcs11.PKCS11Constants;
import org.xipki.security.EdECConstants;
import org.xipki.security.XiSecurityException;

import java.security.PrivateKey;

import static org.xipki.util.Args.notNull;

/**
 * {@link PrivateKey} for PKCS#11 token.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11PrivateKey implements PrivateKey {

  private final P11Identity identity;

  private final String algorithm;

  public P11PrivateKey(P11Identity identity) throws P11TokenException {
    this.identity = notNull(identity, "identity");

    long keyType = identity.getKeyType();
    if (keyType == PKCS11Constants.CKK_RSA) {
      algorithm = "RSA";
    } else if (keyType == PKCS11Constants.CKK_DSA) {
      algorithm = "DSA";
    } else if (keyType == PKCS11Constants.CKK_EC || keyType == PKCS11Constants.CKK_VENDOR_SM2) {
      algorithm = "EC";
    } else if (keyType == PKCS11Constants.CKK_EC_EDWARDS) {
      ASN1ObjectIdentifier curveId = identity.getEcParams();
      algorithm = EdECConstants.getName(curveId);
      // keysize = EdECConstants.getKeyBitSize(EdECConstants.getCurveOid(algorithm));
    } else {
      throw new P11TokenException("unknown key type: " + PKCS11Constants.ckkCodeToName(keyType));
    }
  } // constructor

  public boolean supportsMechanism(long mechanism) {
    return identity.supportsMechanism(mechanism);
  }

  @Override
  public String getFormat() {
    return null;
  }

  @Override
  public byte[] getEncoded() {
    return null;
  }

  @Override
  public String getAlgorithm() {
    return algorithm;
  }

  /**
   * Signs the content.
   * @param mechanism
   *          the mechanism
   * @param parameters
   *          the parameters. Could be {@code null}.
   * @param content
   *          the content to be signed.
   * @return the signature.
   * @throws XiSecurityException
   *           if security error happens
   * @throws P11TokenException
   *           if token error happens.
   */
  public byte[] sign(long mechanism, P11Params parameters, byte[] content)
      throws XiSecurityException, P11TokenException {
    return identity.sign(mechanism, parameters, content);
  }

}
