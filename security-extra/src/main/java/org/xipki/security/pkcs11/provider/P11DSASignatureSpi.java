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
 * PKCS#11 DSA {@link SignatureSpi}.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
public abstract class P11DSASignatureSpi extends SignatureSpi {

  public static class NONE extends P11DSASignatureSpi {

    public NONE() {
      super(null);
    }

  } // class NONE

  public static class SHA1 extends P11DSASignatureSpi {

    public SHA1() {
      super(HashAlgo.SHA1);
    }

  } // class SHA1

  public static class SHA224 extends P11DSASignatureSpi {

    public SHA224() {
      super(HashAlgo.SHA224);
    }

  } // class SHA224

  public static class SHA256 extends P11DSASignatureSpi {

    public SHA256() {
      super(HashAlgo.SHA256);
    }

  } // class SHA256

  public static class SHA384 extends P11DSASignatureSpi {

    public SHA384() {
      super(HashAlgo.SHA384);
    }

  } // class SHA384

  public static class SHA512 extends P11DSASignatureSpi {

    public SHA512() {
      super(HashAlgo.SHA512);
    }

  } // class SHA512

  public static class SHA3_224 extends P11DSASignatureSpi {

    public SHA3_224() {
      super(HashAlgo.SHA3_224);
    }

  } // class SHA3_224

  public static class SHA3_256 extends P11DSASignatureSpi {

    public SHA3_256() {
      super(HashAlgo.SHA3_256);
    }

  } // class SHA3_256

  public static class SHA3_384 extends P11DSASignatureSpi {

    public SHA3_384() {
      super(HashAlgo.SHA3_384);
    }

  } // class SHA3_384

  public static class SHA3_512 extends P11DSASignatureSpi {

    public SHA3_512() {
      super(HashAlgo.SHA3_512);
    }

  } // class SHA3_512

  private final HashAlgo hashAlgo;

  private long mechanism;

  private OutputStream outputStream;

  private P11PrivateKey signingKey;

  private P11DSASignatureSpi(HashAlgo hashAlgo) {
    this.hashAlgo = hashAlgo;
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
    if (!"DSA".equals(algo)) {
      throw new InvalidKeyException("privateKey is not a DSA private key: " + algo);
    }

    this.signingKey = (P11PrivateKey) privateKey;
    if (signingKey.supportsMechanism(PKCS11Constants.CKM_DSA)) {
      mechanism = PKCS11Constants.CKM_DSA;
      if (hashAlgo == null) {
        outputStream = new ByteArrayOutputStream();
      } else {
        outputStream = new DigestOutputStream(hashAlgo.createDigest());
      }
    } else {
      if (hashAlgo == HashAlgo.SHA1
          && signingKey.supportsMechanism(PKCS11Constants.CKM_DSA_SHA1)) {
        mechanism = PKCS11Constants.CKM_DSA_SHA1;
      } else if (hashAlgo == HashAlgo.SHA224
          && signingKey.supportsMechanism(PKCS11Constants.CKM_DSA_SHA224)) {
        mechanism = PKCS11Constants.CKM_DSA_SHA224;
      } else if (hashAlgo == HashAlgo.SHA256
          && signingKey.supportsMechanism(PKCS11Constants.CKM_DSA_SHA256)) {
        mechanism = PKCS11Constants.CKM_DSA_SHA256;
      } else if (hashAlgo == HashAlgo.SHA384
          && signingKey.supportsMechanism(PKCS11Constants.CKM_DSA_SHA384)) {
        mechanism = PKCS11Constants.CKM_DSA_SHA384;
      } else if (hashAlgo == HashAlgo.SHA512
          && signingKey.supportsMechanism(PKCS11Constants.CKM_DSA_SHA512)) {
        mechanism = PKCS11Constants.CKM_DSA_SHA512;
      } else if (hashAlgo == HashAlgo.SHA3_224
          && signingKey.supportsMechanism(PKCS11Constants.CKM_DSA_SHA3_224)) {
        mechanism = PKCS11Constants.CKM_DSA_SHA3_224;
      } else if (hashAlgo == HashAlgo.SHA3_256
          && signingKey.supportsMechanism(PKCS11Constants.CKM_DSA_SHA3_256)) {
        mechanism = PKCS11Constants.CKM_DSA_SHA3_256;
      } else if (hashAlgo == HashAlgo.SHA3_384
          && signingKey.supportsMechanism(PKCS11Constants.CKM_DSA_SHA3_384)) {
        mechanism = PKCS11Constants.CKM_DSA_SHA3_384;
      } else if (hashAlgo == HashAlgo.SHA3_512
          && signingKey.supportsMechanism(PKCS11Constants.CKM_DSA_SHA3_512)) {
        mechanism = PKCS11Constants.CKM_DSA_SHA3_512;
      } else {
        throw new InvalidKeyException("privateKey and algorithm does not match");
      }

      outputStream = new ByteArrayOutputStream();
    }

    this.signingKey = (P11PrivateKey) privateKey;
  } // class engineInitSign

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
      return SignerUtil.dsaSigPlainToX962(plainSignature);
    } catch (P11TokenException | XiSecurityException ex) {
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
