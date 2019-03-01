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

package org.xipki.security.pkcs11.provider;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.xipki.security.HashAlgo;
import org.xipki.security.pkcs11.P11PrivateKey;

import iaik.pkcs.pkcs11.constants.PKCS11Constants;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class P11RSADigestSignatureSpi extends SignatureSpi {

  // CHECKSTYLE:SKIP
  public static class SHA1 extends P11RSADigestSignatureSpi {

    public SHA1() {
      super(HashAlgo.SHA1);
    }

  } // class SHA1

  // CHECKSTYLE:SKIP
  public static class SHA224 extends P11RSADigestSignatureSpi {

    public SHA224() {
      super(HashAlgo.SHA224);
    }

  } // class SHA224

  // CHECKSTYLE:SKIP
  public static class SHA256 extends P11RSADigestSignatureSpi {

    public SHA256() {
      super(HashAlgo.SHA256);
    }

  } // class SHA256

  // CHECKSTYLE:SKIP
  public static class SHA384 extends P11RSADigestSignatureSpi {

    public SHA384() {
      super(HashAlgo.SHA384);
    }

  } // class SHA384

  // CHECKSTYLE:SKIP
  public static class SHA512 extends P11RSADigestSignatureSpi {

    public SHA512() {
      super(HashAlgo.SHA512);
    }

  } // class SHA512

  // CHECKSTYLE:SKIP
  public static class SHA3_224 extends P11RSADigestSignatureSpi {

    public SHA3_224() {
      super(HashAlgo.SHA3_224);
    }

  } // class SHA3-224

  // CHECKSTYLE:SKIP
  public static class SHA3_256 extends P11RSADigestSignatureSpi {

    public SHA3_256() {
      super(HashAlgo.SHA3_256);
    }

  } // class SHA3-256

  // CHECKSTYLE:SKIP
  public static class SHA3_384 extends P11RSADigestSignatureSpi {

    public SHA3_384() {
      super(HashAlgo.SHA3_384);
    }

  } // class SHA3-384

  // CHECKSTYLE:SKIP
  public static class SHA3_512 extends P11RSADigestSignatureSpi {

    public SHA3_512() {
      super(HashAlgo.SHA3_512);
    }

  } // class SHA3-512

  // CHECKSTYLE:SKIP
  public static class NoneRSA extends P11RSADigestSignatureSpi {

    public NoneRSA() {
      super(new NullDigest());
    }

  } // class NoneRSA

  private Digest digest;

  private AlgorithmIdentifier digestAlgId;

  private P11PrivateKey signingKey;

  protected P11RSADigestSignatureSpi(Digest digest) {
    this.digest = digest;
    this.digestAlgId = null;
  }

  protected P11RSADigestSignatureSpi(HashAlgo digestAlg) {
    this.digestAlgId = digestAlg.getAlgorithmIdentifier();
    this.digest = digestAlg.createDigest();
  }

  @Override
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    throw new UnsupportedOperationException("engineVerify unsupported");
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    if (!(privateKey instanceof P11PrivateKey)) {
      throw new InvalidKeyException("privateKey is not instanceof "
          + P11PrivateKey.class.getName());
    }

    String algo = privateKey.getAlgorithm();
    if (!"RSA".equals(algo)) {
      throw new InvalidKeyException("privateKey is not an RSA private key: " + algo);
    }

    digest.reset();
    this.signingKey = (P11PrivateKey) privateKey;
  }

  @Override
  protected void engineUpdate(byte input) throws SignatureException {
    digest.update(input);
  }

  @Override
  protected void engineUpdate(byte[] input, int off, int len) throws SignatureException {
    digest.update(input, off, len);
  }

  @Override
  protected byte[] engineSign() throws SignatureException {
    byte[] hash = new byte[digest.getDigestSize()];
    digest.doFinal(hash, 0);

    try {
      byte[] bytes = derEncode(hash);
      return signingKey.sign(PKCS11Constants.CKM_RSA_PKCS, null, bytes);
    } catch (ArrayIndexOutOfBoundsException ex) {
      throw new SignatureException("key too small for signature type");
    } catch (Exception ex) {
      throw new SignatureException(ex.getMessage(), ex);
    }
  }

  @Override
  protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
    throw new UnsupportedOperationException("engineVerify unsupported");
  }

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
    return null;
  }

  @Override
  protected AlgorithmParameters engineGetParameters() {
    return null;
  }

  private byte[] derEncode(byte[] hash) throws IOException {
    if (digestAlgId == null) {
      // For raw RSA, the DigestInfo must be prepared externally
      return hash;
    }

    DigestInfo digestInfo = new DigestInfo(digestAlgId, hash);
    return digestInfo.getEncoded(ASN1Encoding.DER);
  }

}
