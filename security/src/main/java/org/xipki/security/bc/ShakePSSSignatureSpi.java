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

package org.xipki.security.bc;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.xipki.security.SignAlgo;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.SignerUtil;

/**
 * SHAKE-ECDSA implementation.
 *
 * @author Lijun Liao
 */
// CHECKSTYLE:OFF
public class ShakePSSSignatureSpi
    extends SignatureSpi {
  private RSAKeyParameters key;
  private SecureRandom random;

  private Signer signer;

  // care - this constructor is actually used by outside organisations
  protected ShakePSSSignatureSpi(SignAlgo sigAlgo) {
    try {
      this.signer = SignerUtil.createPSSRSASigner(sigAlgo);
    } catch (XiSecurityException ex) {
      throw new IllegalStateException("ShakePSSSignatureSpi.<cinit>", ex);
    }
  }

  protected void engineInitVerify(
      PublicKey publicKey)
      throws InvalidKeyException {
    if (!(publicKey instanceof RSAPublicKey)) {
      throw new InvalidKeyException("Supplied key is not a RSAPublicKey instance");
    }

    RSAPublicKey rsaPk = (RSAPublicKey) publicKey;
    key = new RSAKeyParameters(false, rsaPk.getModulus(), rsaPk.getPublicExponent());

    signer.init(false, key);
  }

  protected void engineInitSign(
      PrivateKey privateKey,
      SecureRandom random)
      throws InvalidKeyException {
    this.random = random;
    engineInitSign(privateKey);
  }

  protected void engineInitSign(
      PrivateKey privateKey)
      throws InvalidKeyException {
    if (!(privateKey instanceof RSAPrivateKey)) {
      throw new InvalidKeyException("Supplied key is not a RSAPrivateKey instance");
    }

    key = generatePrivateKeyParameter((RSAPrivateKey)privateKey);
    if (random != null) {
      signer.init(true, new ParametersWithRandom(key, random));
    } else {
      signer.init(true, key);
    }
  }

  private static RSAKeyParameters generatePrivateKeyParameter(
      RSAPrivateKey key) {
    if (key instanceof RSAPrivateCrtKey) {
      RSAPrivateCrtKey k = (RSAPrivateCrtKey)key;

      return new RSAPrivateCrtKeyParameters(k.getModulus(),
          k.getPublicExponent(), k.getPrivateExponent(),
          k.getPrimeP(), k.getPrimeQ(), k.getPrimeExponentP(),
          k.getPrimeExponentQ(), k.getCrtCoefficient());
    } else {
      return new RSAKeyParameters(true, key.getModulus(), key.getPrivateExponent());
    }
  }

  protected void engineUpdate(
      byte    b)
      throws SignatureException {
    signer.update(b);
  }

  protected void engineUpdate(
      byte[]  b,
      int     off,
      int     len)
      throws SignatureException {
    signer.update(b, off, len);
  }

  protected byte[] engineSign()
      throws SignatureException {
    try {
      return signer.generateSignature();
    } catch (CryptoException e) {
      throw new SignatureException(e.getMessage());
    }
  }

  protected boolean engineVerify(
      byte[]  sigBytes)
      throws SignatureException {
    return signer.verifySignature(sigBytes);
  }

  protected void engineSetParameter(
      AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
  }

  protected AlgorithmParameters engineGetParameters() {
    return null;
  }

  /**
   * @deprecated replaced with
   * <a href="#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">
   * engineSetParameter(java.security.spec.AlgorithmParameterSpec)</a>
   */
  protected void engineSetParameter(
      String param,
      Object value) {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
  }

  protected Object engineGetParameter(
      String param) {
    throw new UnsupportedOperationException("engineGetParameter unsupported");
  }

  static public class SHAKE128 extends ShakePSSSignatureSpi {
    public SHAKE128() {
      super(SignAlgo.RSAPSS_SHAKE128);
    }
  }

  static public class SHAKE256 extends ShakePSSSignatureSpi {
    public SHAKE256() {
      super(SignAlgo.RSAPSS_SHAKE128);
    }
  }
}
