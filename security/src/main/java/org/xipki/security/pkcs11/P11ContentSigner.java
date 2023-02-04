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
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.XiContentSigner;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.GMUtil;
import org.xipki.security.util.PKCS1Util;
import org.xipki.security.util.SignerUtil;
import org.xipki.util.LogUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;
import static org.xipki.security.HashAlgo.*;
import static org.xipki.util.Args.notNull;

/**
 * PKCS#11 {@link XiContentSigner}.
 *
 * @author Lijun Liao
 *
 */
abstract class P11ContentSigner implements XiContentSigner {

  private static final Logger LOG = LoggerFactory.getLogger(P11ContentSigner.class);

  protected final P11Identity identity;

  protected final SignAlgo signAlgo;

  protected final byte[] encodedAlgorithmIdentifier;

  P11ContentSigner(P11Identity identity, SignAlgo signAlgo) throws XiSecurityException {
    this.identity = notNull(identity, "identity");
    this.signAlgo = notNull(signAlgo, "signAlgo");
    try {
      this.encodedAlgorithmIdentifier = signAlgo.getAlgorithmIdentifier().getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }
  }

  @Override
  public final AlgorithmIdentifier getAlgorithmIdentifier() {
    return signAlgo.getAlgorithmIdentifier();
  }

  @Override
  public final byte[] getEncodedAlgorithmIdentifier() {
    return Arrays.copyOf(encodedAlgorithmIdentifier, encodedAlgorithmIdentifier.length);
  }

  private static class SignerOutputStream extends OutputStream {

    private final Signer pssSigner;

    SignerOutputStream(Signer pssSigner) {
      this.pssSigner = pssSigner;
    }

    @Override
    public void write(int oneByte) throws IOException {
      pssSigner.update((byte) oneByte);
    }

    @Override
    public void write(byte[] bytes) throws IOException {
      pssSigner.update(bytes, 0, bytes.length);
    }

    @Override
    public void write(byte[] bytes, int off, int len) throws IOException {
      pssSigner.update(bytes, off, len);
    }

    public void reset() {
      pssSigner.reset();
    }

    @Override
    public void flush() throws IOException {
    }

    @Override
    public void close() throws IOException {
    }

    byte[] generateSignature() throws DataLengthException, CryptoException {
      byte[] signature = pssSigner.generateSignature();
      pssSigner.reset();
      return signature;
    }

  } // class SignerOutputStream

  static class DSA extends P11ContentSigner {

    private static final Map<HashAlgo, Long> hashMechMap = new HashMap<>();

    private final OutputStream outputStream;

    private final long mechanism;

    static {
      hashMechMap.put(SHA1, CKM_DSA_SHA1);
      hashMechMap.put(SHA224, CKM_DSA_SHA224);
      hashMechMap.put(SHA256, CKM_DSA_SHA256);
      hashMechMap.put(SHA384, CKM_DSA_SHA384);
      hashMechMap.put(SHA512, CKM_DSA_SHA512);
      hashMechMap.put(SHA3_224, CKM_DSA_SHA3_224);
      hashMechMap.put(SHA3_256, CKM_DSA_SHA3_256);
      hashMechMap.put(SHA3_384, CKM_DSA_SHA3_384);
      hashMechMap.put(SHA3_512, CKM_DSA_SHA3_512);
    } // method static

    DSA(P11Identity identity, SignAlgo signAlgo) throws XiSecurityException {
      super(identity, signAlgo);

      if (!signAlgo.isDSASigAlgo()) {
        throw new XiSecurityException("not a DSA algorithm: " + signAlgo);
      }

      Long mech = hashMechMap.get(signAlgo.getHashAlgo());

      if (mech != null && identity.supportsMechanism(mech)) {
        mechanism = mech;
        outputStream = new ByteArrayOutputStream();
      } else if (identity.supportsMechanism(CKM_DSA)) {
        mechanism = CKM_DSA;
        outputStream = new DigestOutputStream(signAlgo.getHashAlgo().createDigest());
      } else {
        throw new XiSecurityException("unsupported signature algorithm " + signAlgo);
      }
    } // constructor

    @Override
    public OutputStream getOutputStream() {
      if (outputStream instanceof ByteArrayOutputStream) {
        ((ByteArrayOutputStream) outputStream).reset();
      } else {
        ((DigestOutputStream) outputStream).reset();
      }
      return outputStream;
    }

    @Override
    public byte[] getSignature() {
      try {
        byte[] plainSignature = getPlainSignature();
        return SignerUtil.dsaSigPlainToX962(plainSignature);
      } catch (XiSecurityException ex) {
        LogUtil.warn(LOG, ex);
        throw new RuntimeCryptoException("XiSecurityException: " + ex.getMessage());
      } catch (Throwable th) {
        LogUtil.warn(LOG, th);
        throw new RuntimeCryptoException(th.getClass().getName() + ": " + th.getMessage());
      }
    }

    private byte[] getPlainSignature() throws XiSecurityException, TokenException {
      byte[] dataToSign;
      if (outputStream instanceof ByteArrayOutputStream) {
        dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
        ((ByteArrayOutputStream) outputStream).reset();
      } else {
        dataToSign = ((DigestOutputStream) outputStream).digest();
        ((DigestOutputStream) outputStream).reset();
      }

      return identity.sign(mechanism, null, dataToSign);
    }

  } // class DSA

  static class ECDSA extends P11ContentSigner {

    private static final Map<HashAlgo, Long> hashMechMap = new HashMap<>();

    private final OutputStream outputStream;

    private final long mechanism;

    static {
      hashMechMap.put(SHA1,   CKM_ECDSA_SHA1);
      hashMechMap.put(SHA224, CKM_ECDSA_SHA224);
      hashMechMap.put(SHA256, CKM_ECDSA_SHA256);
      hashMechMap.put(SHA384, CKM_ECDSA_SHA384);
      hashMechMap.put(SHA512, CKM_ECDSA_SHA512);
      hashMechMap.put(SHA3_224, CKM_ECDSA_SHA3_224);
      hashMechMap.put(SHA3_256, CKM_ECDSA_SHA3_256);
      hashMechMap.put(SHA3_384, CKM_ECDSA_SHA3_384);
      hashMechMap.put(SHA3_512, CKM_ECDSA_SHA3_512);
    } // method static

    ECDSA(P11Identity identity, SignAlgo signAlgo) throws XiSecurityException {
      super(identity, signAlgo);
      if (!signAlgo.isECDSASigAlgo()) {
        throw new XiSecurityException("not an ECDSA algorithm: " + signAlgo);
      }

      Long mech = hashMechMap.get(signAlgo.getHashAlgo());

      if (mech != null && identity.supportsMechanism(mech)) {
        mechanism = mech;
        this.outputStream = new ByteArrayOutputStream();
      } else if (identity.supportsMechanism(CKM_ECDSA)) {
        mechanism = CKM_ECDSA;
        this.outputStream = new DigestOutputStream(signAlgo.getHashAlgo().createDigest());
      } else {
        throw new XiSecurityException("unsupported signature algorithm " + signAlgo);
      }
    } // method constructor

    @Override
    public OutputStream getOutputStream() {
      if (outputStream instanceof ByteArrayOutputStream) {
        ((ByteArrayOutputStream) outputStream).reset();
      } else {
        ((DigestOutputStream) outputStream).reset();
      }
      return outputStream;
    }

    @Override
    public byte[] getSignature() {
      try {
        byte[] plainSignature = getPlainSignature();
        return signAlgo.isPlainECDSASigAlgo() ? plainSignature : SignerUtil.dsaSigPlainToX962(plainSignature);
      } catch (XiSecurityException ex) {
        LogUtil.warn(LOG, ex);
        throw new RuntimeCryptoException("XiSecurityException: " + ex.getMessage());
      } catch (Throwable th) {
        LogUtil.warn(LOG, th);
        throw new RuntimeCryptoException(th.getClass().getName() + ": " + th.getMessage());
      }
    }

    private byte[] getPlainSignature() throws XiSecurityException, TokenException {
      byte[] dataToSign;
      if (outputStream instanceof ByteArrayOutputStream) {
        dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
        ((ByteArrayOutputStream) outputStream).reset();
      } else {
        dataToSign = ((DigestOutputStream) outputStream).digest();
        ((DigestOutputStream) outputStream).reset();
      }

      return identity.sign(mechanism, null, dataToSign);
    }
  } // method ECDSA

  static class EdDSA extends P11ContentSigner {

    private final ByteArrayOutputStream outputStream;

    private final long mechanism;

    EdDSA(P11Identity identity, SignAlgo signAlgo) throws XiSecurityException {
      super(identity, signAlgo);

      if (SignAlgo.ED25519 != signAlgo) {
        throw new XiSecurityException("unsupported signature algorithm " + signAlgo);
      }

      mechanism = CKM_EDDSA;
      if (!identity.supportsMechanism(mechanism)) {
        throw new XiSecurityException("unsupported signature algorithm " + signAlgo);
      }

      this.outputStream = new ByteArrayOutputStream();
    }

    @Override
    public OutputStream getOutputStream() {
      outputStream.reset();
      return outputStream;
    }

    @Override
    public byte[] getSignature() {
      byte[] content = outputStream.toByteArray();
      outputStream.reset();
      try {
        return identity.sign(mechanism, null, content);
      } catch (Throwable th) {
        LogUtil.warn(LOG, th);
        throw new RuntimeCryptoException(th.getClass().getName() + ": " + th.getMessage());
      }
    }

  } // class EdDSA

  static class Mac extends P11ContentSigner {

    private static final Map<HashAlgo, Long> hashMechMap = new HashMap<>();

    private final long mechanism;

    private final ByteArrayOutputStream outputStream;

    static {
      hashMechMap.put(SHA1,   CKM_SHA_1_HMAC);
      hashMechMap.put(SHA224, CKM_SHA224_HMAC);
      hashMechMap.put(SHA256, CKM_SHA256_HMAC);
      hashMechMap.put(SHA384, CKM_SHA384_HMAC);
      hashMechMap.put(SHA512, CKM_SHA512_HMAC);
      hashMechMap.put(SHA3_224, CKM_SHA3_224_HMAC);
      hashMechMap.put(SHA3_256, CKM_SHA3_256_HMAC);
      hashMechMap.put(SHA3_384, CKM_SHA3_384_HMAC);
      hashMechMap.put(SHA3_512, CKM_SHA3_512_HMAC);
    } // method static

    Mac(P11Identity identity, SignAlgo signAlgo) throws XiSecurityException {
      super(identity, signAlgo);

      HashAlgo hashAlgo = signAlgo.getHashAlgo();
      Long mech = hashMechMap.get(hashAlgo);
      if (mech == null) {
        throw new XiSecurityException("Unsupported signature algorithm " + signAlgo);
      }

      this.mechanism = mech;
      if (identity.supportsMechanism(mechanism)) {
        throw new XiSecurityException("unsupported MAC algorithm " + signAlgo);
      }

      this.outputStream = new ByteArrayOutputStream();
    } // constructor

    @Override
    public OutputStream getOutputStream() {
      outputStream.reset();
      return outputStream;
    }

    @Override
    public byte[] getSignature() {
      try {
        byte[] dataToSign = outputStream.toByteArray();
        outputStream.reset();
        return identity.sign(mechanism, null, dataToSign);
      } catch (TokenException ex) {
        LogUtil.warn(LOG, ex);
        throw new RuntimeCryptoException("TokenException: " + ex.getMessage());
      } catch (Throwable th) {
        LogUtil.warn(LOG, th);
        throw new RuntimeCryptoException(th.getClass().getName() + ": " + th.getMessage());
      }
    }

  } // class Mac

  static class RSA extends P11ContentSigner {

    private static final Map<HashAlgo, Long> hashMechMap = new HashMap<>();

    private final long mechanism;

    private final OutputStream outputStream;

    private final byte[] digestPkcsPrefix;

    private final int modulusBitLen;

    static {
      hashMechMap.put(SHA1,   CKM_SHA1_RSA_PKCS);
      hashMechMap.put(SHA224, CKM_SHA224_RSA_PKCS);
      hashMechMap.put(SHA256, CKM_SHA256_RSA_PKCS);
      hashMechMap.put(SHA384, CKM_SHA384_RSA_PKCS);
      hashMechMap.put(SHA512, CKM_SHA512_RSA_PKCS);
      hashMechMap.put(SHA3_224, CKM_SHA3_224_RSA_PKCS);
      hashMechMap.put(SHA3_256, CKM_SHA3_256_RSA_PKCS);
      hashMechMap.put(SHA3_384, CKM_SHA3_384_RSA_PKCS);
      hashMechMap.put(SHA3_512, CKM_SHA3_512_RSA_PKCS);
    } // method static

    RSA(P11Identity identity, SignAlgo signAlgo) throws XiSecurityException {
      super(identity, signAlgo);

      if (!signAlgo.isRSAPkcs1SigAlgo()) {
        throw new XiSecurityException("not an RSA PKCS#1 algorithm: " + signAlgo);
      }

      HashAlgo hashAlgo = signAlgo.getHashAlgo();
      Long mech = hashMechMap.get(hashAlgo);

      if (mech != null && identity.supportsMechanism(mech)) {
        mechanism = mech;
      } else if (identity.supportsMechanism(CKM_RSA_PKCS)) {
        mechanism = CKM_RSA_PKCS;
      } else if (identity.supportsMechanism(CKM_RSA_X_509)) {
        mechanism = CKM_RSA_X_509;
      } else {
        throw new XiSecurityException("unsupported signature algorithm " + signAlgo);
      }

      if (mechanism == CKM_RSA_PKCS || mechanism == CKM_RSA_X_509) {
        this.digestPkcsPrefix = PKCS1Util.getDigestPkcsPrefix(hashAlgo);
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else {
        this.digestPkcsPrefix = null;
        this.outputStream = new ByteArrayOutputStream();
      }

      this.modulusBitLen = identity.getRsaModulus().bitLength();
    } // constructor

    @Override
    public OutputStream getOutputStream() {
      if (outputStream instanceof ByteArrayOutputStream) {
        ((ByteArrayOutputStream) outputStream).reset();
      } else {
        ((DigestOutputStream) outputStream).reset();
      }
      return outputStream;
    }

    @Override
    public byte[] getSignature() {
      byte[] dataToSign;
      if (outputStream instanceof ByteArrayOutputStream) {
        dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
        ((ByteArrayOutputStream) outputStream).reset();
      } else {
        byte[] hashValue = ((DigestOutputStream) outputStream).digest();
        ((DigestOutputStream) outputStream).reset();
        dataToSign = new byte[digestPkcsPrefix.length + hashValue.length];
        System.arraycopy(digestPkcsPrefix, 0, dataToSign, 0, digestPkcsPrefix.length);
        System.arraycopy(hashValue, 0, dataToSign, digestPkcsPrefix.length, hashValue.length);
      }

      try {
        if (mechanism == CKM_RSA_X_509) {
          dataToSign = PKCS1Util.EMSA_PKCS1_v1_5_encoding(dataToSign, modulusBitLen);
        }

        return identity.sign(mechanism, null, dataToSign);
      } catch (XiSecurityException | TokenException ex) {
        LogUtil.error(LOG, ex, "could not sign");
        throw new RuntimeCryptoException("SignerException: " + ex.getMessage());
      }
    } // method getSignature

  } // class RSA

  static class RSAPSS extends P11ContentSigner {

    private static final Map<HashAlgo, Long> hashMechMap = new HashMap<>();

    static {
      hashMechMap.put(SHA1,   CKM_SHA1_RSA_PKCS_PSS);
      hashMechMap.put(SHA224, CKM_SHA224_RSA_PKCS_PSS);
      hashMechMap.put(SHA256, CKM_SHA256_RSA_PKCS_PSS);
      hashMechMap.put(SHA384, CKM_SHA384_RSA_PKCS_PSS);
      hashMechMap.put(SHA512, CKM_SHA512_RSA_PKCS_PSS);
      hashMechMap.put(SHA3_224, CKM_SHA3_224_RSA_PKCS_PSS);
      hashMechMap.put(SHA3_256, CKM_SHA3_256_RSA_PKCS_PSS);
      hashMechMap.put(SHA3_384, CKM_SHA3_384_RSA_PKCS_PSS);
      hashMechMap.put(SHA3_512, CKM_SHA3_512_RSA_PKCS_PSS);
    } // method static

    private final long mechanism;

    private final P11Params.P11RSAPkcsPssParams parameters;

    private final OutputStream outputStream;

    RSAPSS(P11Identity identity, SignAlgo signAlgo, SecureRandom random) throws XiSecurityException {
      super(identity, signAlgo);
      if (!signAlgo.isRSAPSSSigAlgo()) {
        throw new XiSecurityException("not an RSA PSS algorithm: " + signAlgo);
      }

      notNull(random, "random");
      HashAlgo hashAlgo = signAlgo.getHashAlgo();

      Long mech = hashMechMap.get(hashAlgo);
      if (mech != null && identity.supportsMechanism(mech)) {
        this.mechanism = mech;
        this.parameters = new P11Params.P11RSAPkcsPssParams(hashAlgo);
        this.outputStream = new ByteArrayOutputStream();
      } else if (!signAlgo.getHashAlgo().isShake() && identity.supportsMechanism(CKM_RSA_PKCS_PSS)) {
        this.mechanism = CKM_RSA_PKCS_PSS;
        this.parameters = new P11Params.P11RSAPkcsPssParams(hashAlgo);
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else if (identity.supportsMechanism(CKM_RSA_X_509)) {
        this.mechanism = CKM_RSA_X_509;
        this.parameters = null;
        AsymmetricBlockCipher cipher = new P11PlainRSASigner();
        P11RSAKeyParameter keyParam = new P11RSAKeyParameter(identity);
        Signer pssSigner = SignerUtil.createPSSRSASigner(signAlgo, cipher);
        pssSigner.init(true, new ParametersWithRandom(keyParam, random));
        this.outputStream = new SignerOutputStream(pssSigner);
      } else {
        throw new XiSecurityException("unsupported signature algorithm " + signAlgo);
      }
    } // constructor

    @Override
    public OutputStream getOutputStream() {
      if (outputStream instanceof ByteArrayOutputStream) {
        ((ByteArrayOutputStream) outputStream).reset();
      } else if (outputStream instanceof DigestOutputStream) {
        ((DigestOutputStream) outputStream).reset();
      } else {
        ((SignerOutputStream) outputStream).reset();
      }

      return outputStream;
    }

    @Override
    public byte[] getSignature() {
      if (outputStream instanceof SignerOutputStream) {
        try {
          return ((SignerOutputStream) outputStream).generateSignature();
        } catch (CryptoException ex) {
          LogUtil.warn(LOG, ex);
          throw new RuntimeCryptoException("CryptoException: " + ex.getMessage());
        }
      }

      byte[] dataToSign;
      if (outputStream instanceof ByteArrayOutputStream) {
        dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
      } else {
        dataToSign = ((DigestOutputStream) outputStream).digest();
      }

      try {
        return identity.sign(mechanism, parameters, dataToSign);
      } catch (TokenException ex) {
        LogUtil.warn(LOG, ex, "could not sign");
        throw new RuntimeCryptoException("SignerException: " + ex.getMessage());
      }

    } // method getSignature

  } // class RSAPSS

  static class SM2 extends P11ContentSigner {

    private static final Map<HashAlgo, Long> hashMechMap = new HashMap<>();

    private final long mechanism;

    private final OutputStream outputStream;

    private final byte[] z;

    static {
      hashMechMap.put(SM3, CKM_VENDOR_SM2_SM3);
    }

    SM2(P11Identity identity, SignAlgo signAlgo, ASN1ObjectIdentifier curveOid,
        BigInteger pubPointX, BigInteger pubPointY) throws XiSecurityException {
      super(identity, signAlgo);
      if (!signAlgo.isSM2SigAlgo()) {
        throw new XiSecurityException("not an SM2 algorithm: " + signAlgo);
      }

      HashAlgo hashAlgo = signAlgo.getHashAlgo();
      Long mech = hashMechMap.get(hashAlgo);
      if (mech != null && identity.supportsMechanism(mech)) {
        this.mechanism = mech;
        this.z = null; // not required
        this.outputStream = new ByteArrayOutputStream();
      } else if (identity.supportsMechanism(CKM_VENDOR_SM2)) {
        this.mechanism = CKM_VENDOR_SM2;
        this.z = GMUtil.getSM2Z(curveOid, pubPointX, pubPointY);
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else {
        throw new XiSecurityException("unsupported signature algorithm " + signAlgo);
      }
    }

    @Override
    public OutputStream getOutputStream() {
      reset();
      return outputStream;
    }

    private void reset() {
      if (outputStream instanceof ByteArrayOutputStream) {
        ((ByteArrayOutputStream) outputStream).reset();
      } else {
        ((DigestOutputStream) outputStream).reset();
        try {
          outputStream.write(z, 0, z.length);
        } catch (IOException ex) {
          throw new IllegalStateException(ex.getMessage());
        }
      }
    }

    @Override
    public byte[] getSignature() {
      try {
        return SignerUtil.dsaSigPlainToX962(getPlainSignature());
      } catch (XiSecurityException ex) {
        LogUtil.warn(LOG, ex);
        throw new RuntimeCryptoException("XiSecurityException: " + ex.getMessage());
      } catch (Throwable th) {
        LogUtil.warn(LOG, th);
        throw new RuntimeCryptoException(th.getClass().getName() + ": " + th.getMessage());
      }
    }

    private byte[] getPlainSignature() throws XiSecurityException, TokenException {
      byte[] dataToSign;
      P11Params.P11ByteArrayParams params;
      if (outputStream instanceof ByteArrayOutputStream) {
        // dataToSign is the real message
        params = new P11Params.P11ByteArrayParams(GMUtil.getDefaultIDA());
        dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
      } else {
        // dataToSign is Hash(Z||Real Message)
        params = null;
        dataToSign = ((DigestOutputStream) outputStream).digest();
      }

      reset();

      return identity.sign(mechanism, params, dataToSign);
    }
  } // class SM2

}
