/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.xipki.security.EdECConstants;
import org.xipki.security.XiSecurityException;
import org.xipki.util.Args;

/**
 * {@link PrivateKey} for PKCS#11 token.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11PrivateKey implements PrivateKey {

  private static final long serialVersionUID = 1L;

  private final P11CryptService p11CryptService;

  private final P11IdentityId identityId;

  private final String algorithm;

  private final int keysize;

  private final PublicKey publicKey;

  public P11PrivateKey(P11CryptService p11CryptService, P11IdentityId identityId)
      throws P11TokenException {
    this.p11CryptService = Args.notNull(p11CryptService, "p11CryptService");
    this.identityId = Args.notNull(identityId, "identityId");

    this.publicKey = p11CryptService.getIdentity(identityId).getPublicKey();

    if (publicKey instanceof RSAPublicKey) {
      algorithm = "RSA";
      keysize = ((RSAPublicKey) publicKey).getModulus().bitLength();
    } else if (publicKey instanceof DSAPublicKey) {
      algorithm = "DSA";
      keysize = ((DSAPublicKey) publicKey).getParams().getP().bitLength();
    } else if (publicKey instanceof ECPublicKey) {
      algorithm = "EC";
      keysize = ((ECPublicKey) publicKey).getParams().getCurve().getField().getFieldSize();
    } else if (publicKey instanceof EdDSAKey) {
      algorithm = publicKey.getAlgorithm();
      keysize = EdECConstants.getKeyBitSize(EdECConstants.getCurveOid(algorithm));
    } else {
      throw new P11TokenException("unknown public key: " + publicKey);
    }
  } // constructor

  public boolean supportsMechanism(long mechanism) {
    try {
      return p11CryptService.getSlot(identityId.getSlotId()).supportsMechanism(mechanism);
    } catch (P11TokenException ex) {
      return false;
    }
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

  public int getKeysize() {
    return keysize;
  }

  public PublicKey getPublicKey() {
    return publicKey;
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
    return p11CryptService.getIdentity(identityId).sign(mechanism, parameters, content);
  }

  public P11CryptService getP11CryptService() {
    return p11CryptService;
  }

  public P11IdentityId getIdentityId() {
    return identityId;
  }

}
