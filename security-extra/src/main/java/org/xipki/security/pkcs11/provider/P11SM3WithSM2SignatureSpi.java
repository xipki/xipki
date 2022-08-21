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

package org.xipki.security.pkcs11.provider;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.xipki.security.HashAlgo;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.DigestOutputStream;
import org.xipki.security.pkcs11.P11Params;
import org.xipki.security.pkcs11.P11Params.P11ByteArrayParams;
import org.xipki.security.pkcs11.P11PrivateKey;
import org.xipki.security.pkcs11.P11TokenException;
import org.xipki.security.util.GMUtil;
import org.xipki.security.util.SignerUtil;
import org.xipki.util.StringUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECPoint;

/**
 * PKCS#11 SM3withSM2 {@link SignatureSpi}.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
public class P11SM3WithSM2SignatureSpi extends SignatureSpi {

  private long mechanism;

  private OutputStream outputStream;

  private P11PrivateKey signingKey;

  private XiSM2ParameterSpec paramSpec;

  private byte[] sm2Z;

  private P11Params p11Params;

  public P11SM3WithSM2SignatureSpi() {
  }

  @Override
  protected void engineInitVerify(PublicKey publicKey)
      throws InvalidKeyException {
    throw new UnsupportedOperationException("engineInitVerify unsupported");
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey)
      throws InvalidKeyException {
    if (!(privateKey instanceof P11PrivateKey)) {
      throw new InvalidKeyException("privateKey is not instanceof " + P11PrivateKey.class.getName());
    }

    this.signingKey = (P11PrivateKey) privateKey;
    if (!(signingKey.getPublicKey() instanceof ECPublicKey)) {
      throw new InvalidKeyException("only EC key is allowed");
    }

    ECPublicKey pubKey = (ECPublicKey) signingKey.getPublicKey();
    if (!GMUtil.isSm2primev2Curve(pubKey.getParams().getCurve())) {
      throw new InvalidKeyException("only EC key of curve sm2primev2 is allowed");
    }

    String algo = privateKey.getAlgorithm();
    if (!("EC".equals(algo) || "ECDSA".equals(algo))) {
      throw new InvalidKeyException("privateKey is not an EC private key: " + algo);
    }

    byte[] userId = (paramSpec == null) ? StringUtil.toUtf8Bytes("1234567812345678") : paramSpec.getId();

    if (signingKey.supportsMechanism(PKCS11Constants.CKM_VENDOR_SM2)) {
      mechanism = PKCS11Constants.CKM_VENDOR_SM2;
      outputStream = new DigestOutputStream(HashAlgo.SM3.createDigest());
      p11Params = null;

      ECPoint w = pubKey.getW();

      sm2Z = GMUtil.getSM2Z(userId, GMObjectIdentifiers.sm2p256v1, w.getAffineX(), w.getAffineY());
      try {
        outputStream.write(sm2Z, 0, sm2Z.length);
      } catch (IOException ex) {
        throw new InvalidKeyException("could not compute Z of SM2");
      }
    } else if (signingKey.supportsMechanism(PKCS11Constants.CKM_VENDOR_SM2_SM3)) {
      mechanism = PKCS11Constants.CKM_VENDOR_SM2_SM3;
      outputStream = new ByteArrayOutputStream();
      p11Params = new P11ByteArrayParams(userId);
    } else {
      throw new InvalidKeyException("privateKey and algorithm does not match");
    }

    this.signingKey = (P11PrivateKey) privateKey;
  } // method engineInitSign

  @Override
  protected void engineUpdate(byte input)
      throws SignatureException {
    try {
      outputStream.write(input);
    } catch (IOException ex) {
      throw new SignatureException("IOException: " + ex.getMessage(), ex);
    }
  }

  @Override
  protected void engineUpdate(byte[] input, int off, int len)
      throws SignatureException {
    try {
      outputStream.write(input, off, len);
    } catch (IOException ex) {
      throw new SignatureException("IOException: " + ex.getMessage(), ex);
    }
  }

  @Override
  protected byte[] engineSign()
      throws SignatureException {
    byte[] dataToSign;
    if (outputStream instanceof ByteArrayOutputStream) {
      dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
      ((ByteArrayOutputStream) outputStream).reset();
    } else {
      dataToSign = ((DigestOutputStream) outputStream).digest();
      ((DigestOutputStream) outputStream).reset();
      try {
        outputStream.write(sm2Z, 0, sm2Z.length);
      } catch (IOException ex) {
        throw new SignatureException(ex.getMessage(), ex);
      }
    }

    try {
      byte[] plainSignature = signingKey.sign(mechanism, p11Params, dataToSign);
      return SignerUtil.dsaSigPlainToX962(plainSignature);
    } catch (XiSecurityException | P11TokenException ex) {
      throw new SignatureException(ex.getMessage(), ex);
    }
  } // method engineSign

  @Override
  protected void engineSetParameter(AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    if (params instanceof XiSM2ParameterSpec) {
      paramSpec = (XiSM2ParameterSpec)params;
    } else {
      throw new InvalidAlgorithmParameterException("only XiSM2ParameterSpec supported");
    }
  }

  @Override
  protected void engineSetParameter(String param, Object value) {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
  }

  @Override
  protected Object engineGetParameter(String param) {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
  }

  @Override
  protected boolean engineVerify(byte[] sigBytes)
      throws SignatureException {
    throw new UnsupportedOperationException("engineVerify unsupported");
  }

}
