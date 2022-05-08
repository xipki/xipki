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
import org.xipki.security.HashAlgo;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.DigestOutputStream;
import org.xipki.security.pkcs11.P11PrivateKey;
import org.xipki.security.pkcs11.P11TokenException;
import org.xipki.security.util.SignerUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * PKCS#11 ECDSA/Plain-ECDSA {@link SignatureSpi}.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
abstract class AbstractP11ECDSASignatureSpi extends SignatureSpi {

  private final HashAlgo hashAlgo;

  private final boolean plain;

  private long mechanism;

  private OutputStream outputStream;

  private P11PrivateKey signingKey;

  /**
   * Constructor.
   *
   * @param hashAlgo
   *          hash algorithm. Could be {@code null}.
   */
  AbstractP11ECDSASignatureSpi(HashAlgo hashAlgo, boolean plain) {
    this.hashAlgo = hashAlgo;
    this.plain = plain;
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
      throw new InvalidKeyException("privateKey is not instanceof "
          + P11PrivateKey.class.getName());
    }
    String algo = privateKey.getAlgorithm();
    if (!("EC".equals(algo) || "ECDSA".equals(algo))) {
      throw new InvalidKeyException("privateKey is not an EC private key: " + algo);
    }

    this.signingKey = (P11PrivateKey) privateKey;
    if (signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA)) {
      mechanism = PKCS11Constants.CKM_ECDSA;
      if (hashAlgo == null) {
        outputStream = new ByteArrayOutputStream();
      } else {
        outputStream = new DigestOutputStream(hashAlgo.createDigest());
      }
    } else {
      if (hashAlgo == HashAlgo.SHA1
          && signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA_SHA1)) {
        mechanism = PKCS11Constants.CKM_ECDSA_SHA1;
      } else if (hashAlgo == HashAlgo.SHA224
          && signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA_SHA224)) {
        mechanism = PKCS11Constants.CKM_ECDSA_SHA224;
      } else if (hashAlgo == HashAlgo.SHA256
          && signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA_SHA256)) {
        mechanism = PKCS11Constants.CKM_ECDSA_SHA256;
      } else if (hashAlgo == HashAlgo.SHA384
          && signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA_SHA384)) {
        mechanism = PKCS11Constants.CKM_ECDSA_SHA384;
      } else if (hashAlgo == HashAlgo.SHA512
          && signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA_SHA512)) {
        mechanism = PKCS11Constants.CKM_ECDSA_SHA512;
      } else if (hashAlgo == HashAlgo.SHA3_224
          && signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA_SHA3_224)) {
        mechanism = PKCS11Constants.CKM_ECDSA_SHA3_224;
      } else if (hashAlgo == HashAlgo.SHA3_256
          && signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA_SHA3_256)) {
        mechanism = PKCS11Constants.CKM_ECDSA_SHA3_256;
      } else if (hashAlgo == HashAlgo.SHA3_384
          && signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA_SHA3_384)) {
        mechanism = PKCS11Constants.CKM_ECDSA_SHA3_384;
      } else if (hashAlgo == HashAlgo.SHA3_512
          && signingKey.supportsMechanism(PKCS11Constants.CKM_ECDSA_SHA3_512)) {
        mechanism = PKCS11Constants.CKM_ECDSA_SHA3_512;
      } else {
        throw new InvalidKeyException("privateKey and algorithm does not match");
      }
      outputStream = new ByteArrayOutputStream();
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
    }

    try {
      byte[] plainSignature = signingKey.sign(mechanism, null, dataToSign);
      return plain ? plainSignature : SignerUtil.dsaSigPlainToX962(plainSignature);
    } catch (XiSecurityException | P11TokenException ex) {
      throw new SignatureException(ex.getMessage(), ex);
    }
  } // method engineSign

  @Override
  protected void engineSetParameter(AlgorithmParameterSpec params) {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
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
