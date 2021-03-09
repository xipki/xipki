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

import static org.xipki.security.HashAlgo.SHA1;
import static org.xipki.security.HashAlgo.SHA224;
import static org.xipki.security.HashAlgo.SHA256;
import static org.xipki.security.HashAlgo.SHA384;
import static org.xipki.security.HashAlgo.SHA3_224;
import static org.xipki.security.HashAlgo.SHA3_256;
import static org.xipki.security.HashAlgo.SHA3_384;
import static org.xipki.security.HashAlgo.SHA3_512;
import static org.xipki.security.HashAlgo.SHA512;
import static org.xipki.security.HashAlgo.SM3;
import static org.xipki.util.Args.notNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.XiContentSigner;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.GMUtil;
import org.xipki.security.util.SignerUtil;
import org.xipki.util.LogUtil;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * PKCS#11 {@link XiContentSigner}.
 *
 * @author Lijun Liao
 *
 */
abstract class P11ContentSigner implements XiContentSigner {

  private static final Logger LOG = LoggerFactory.getLogger(P11ContentSigner.class);

  protected final P11CryptService cryptService;

  protected final P11IdentityId identityId;

  protected final SignAlgo sigAlgo;

  protected final byte[] encodedAlgorithmIdentifier;

  P11ContentSigner(P11CryptService cryptService, P11IdentityId identityId,
      SignAlgo sigAlgo)
      throws XiSecurityException, P11TokenException {
    this.identityId = notNull(identityId, "identityId");
    this.cryptService = notNull(cryptService, "cryptService");
    this.sigAlgo = notNull(sigAlgo, "sigAlgo");
    try {
      this.encodedAlgorithmIdentifier = sigAlgo.getAlgorithmIdentifier().getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }
  }

  @Override
  public final AlgorithmIdentifier getAlgorithmIdentifier() {
    return sigAlgo.getAlgorithmIdentifier();
  }

  @Override
  public final byte[] getEncodedAlgorithmIdentifier() {
    return Arrays.copyOf(encodedAlgorithmIdentifier, encodedAlgorithmIdentifier.length);
  }

  // CHECKSTYLE:SKIP
  private static class SignerOutputStream extends OutputStream {

    private Signer pssSigner;

    SignerOutputStream(Signer pssSigner) {
      this.pssSigner = pssSigner;
    }

    @Override
    public void write(int oneByte)
        throws IOException {
      pssSigner.update((byte) oneByte);
    }

    @Override
    public void write(byte[] bytes)
        throws IOException {
      pssSigner.update(bytes, 0, bytes.length);
    }

    @Override
    public void write(byte[] bytes, int off, int len)
        throws IOException {
      pssSigner.update(bytes, off, len);
    }

    public void reset() {
      pssSigner.reset();
    }

    @Override
    public void flush()
        throws IOException {
    }

    @Override
    public void close()
        throws IOException {
    }

    byte[] generateSignature()
        throws DataLengthException, CryptoException {
      byte[] signature = pssSigner.generateSignature();
      pssSigner.reset();
      return signature;
    }

  } // class SignerOutputStream

  // CHECKSTYLE:SKIP
  static class DSA extends P11ContentSigner {

    private static final Map<HashAlgo, Long> hashMechMap = new HashMap<>();

    private final OutputStream outputStream;

    private final long mechanism;

    static {
      hashMechMap.put(SHA1, PKCS11Constants.CKM_DSA_SHA1);
      hashMechMap.put(SHA224, PKCS11Constants.CKM_DSA_SHA224);
      hashMechMap.put(SHA256, PKCS11Constants.CKM_DSA_SHA256);
      hashMechMap.put(SHA384, PKCS11Constants.CKM_DSA_SHA384);
      hashMechMap.put(SHA512, PKCS11Constants.CKM_DSA_SHA512);
      hashMechMap.put(SHA3_224, PKCS11Constants.CKM_DSA_SHA3_224);
      hashMechMap.put(SHA3_256, PKCS11Constants.CKM_DSA_SHA3_256);
      hashMechMap.put(SHA3_384, PKCS11Constants.CKM_DSA_SHA3_384);
      hashMechMap.put(SHA3_512, PKCS11Constants.CKM_DSA_SHA3_512);
    } // method static

    DSA(P11CryptService cryptService, P11IdentityId identityId, SignAlgo sigAlgo)
        throws XiSecurityException, P11TokenException {
      super(cryptService, identityId, sigAlgo);

      if (!sigAlgo.isDSASigAlgo()) {
        throw new XiSecurityException("not a DSA algorithm: " + sigAlgo);
      }

      Long mech = hashMechMap.get(sigAlgo.getHashAlgo());
      P11Slot slot = cryptService.getSlot(identityId.getSlotId());

      if (mech != null && slot.supportsMechanism(mech)) {
        mechanism = mech;
        this.outputStream = new ByteArrayOutputStream();
      } else if (slot.supportsMechanism(PKCS11Constants.CKM_DSA)) {
        mechanism = PKCS11Constants.CKM_DSA;
        this.outputStream = new DigestOutputStream(sigAlgo.getHashAlgo().createDigest());
      } else {
        throw new XiSecurityException("unsupported signature algorithm " + sigAlgo);
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

    private byte[] getPlainSignature()
        throws XiSecurityException, P11TokenException {
      byte[] dataToSign;
      if (outputStream instanceof ByteArrayOutputStream) {
        dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
        ((ByteArrayOutputStream) outputStream).reset();
      } else {
        dataToSign = ((DigestOutputStream) outputStream).digest();
        ((DigestOutputStream) outputStream).reset();
      }

      return cryptService.getIdentity(identityId).sign(mechanism, null, dataToSign);
    }

  } // class DSA

  // CHECKSTYLE:SKIP
  static class ECDSA extends P11ContentSigner {

    private static final Map<HashAlgo, Long> hashMechMap = new HashMap<>();

    private final OutputStream outputStream;

    private final long mechanism;

    static {
      hashMechMap.put(SHA1, PKCS11Constants.CKM_ECDSA_SHA1);
      hashMechMap.put(SHA224, PKCS11Constants.CKM_ECDSA_SHA224);
      hashMechMap.put(SHA256, PKCS11Constants.CKM_ECDSA_SHA256);
      hashMechMap.put(SHA384, PKCS11Constants.CKM_ECDSA_SHA384);
      hashMechMap.put(SHA512, PKCS11Constants.CKM_ECDSA_SHA512);
      hashMechMap.put(SHA3_224, PKCS11Constants.CKM_ECDSA_SHA3_224);
      hashMechMap.put(SHA3_256, PKCS11Constants.CKM_ECDSA_SHA3_256);
      hashMechMap.put(SHA3_384, PKCS11Constants.CKM_ECDSA_SHA3_384);
      hashMechMap.put(SHA3_512, PKCS11Constants.CKM_ECDSA_SHA3_512);
    } // method static

    ECDSA(P11CryptService cryptService, P11IdentityId identityId, SignAlgo sigAlgo)
        throws XiSecurityException, P11TokenException {
      super(cryptService, identityId, sigAlgo);
      if (!sigAlgo.isECDSASigAlgo()) {
        throw new XiSecurityException("not an ECDSA algorithm: " + sigAlgo);
      }

      Long mech = hashMechMap.get(sigAlgo.getHashAlgo());

      P11Slot slot = cryptService.getSlot(identityId.getSlotId());
      if (mech != null && slot.supportsMechanism(mech)) {
        mechanism = mech;
        this.outputStream = new ByteArrayOutputStream();
      } else if (slot.supportsMechanism(PKCS11Constants.CKM_ECDSA)) {
        mechanism = PKCS11Constants.CKM_ECDSA;
        this.outputStream = new DigestOutputStream(sigAlgo.getHashAlgo().createDigest());
      } else {
        throw new XiSecurityException("unsupported signature algorithm " + sigAlgo);
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
        return sigAlgo.isPlainECDSASigAlgo() ? plainSignature
            : SignerUtil.dsaSigPlainToX962(plainSignature);
      } catch (XiSecurityException ex) {
        LogUtil.warn(LOG, ex);
        throw new RuntimeCryptoException("XiSecurityException: " + ex.getMessage());
      } catch (Throwable th) {
        LogUtil.warn(LOG, th);
        throw new RuntimeCryptoException(th.getClass().getName() + ": " + th.getMessage());
      }
    }

    private byte[] getPlainSignature()
        throws XiSecurityException, P11TokenException {
      byte[] dataToSign;
      if (outputStream instanceof ByteArrayOutputStream) {
        dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
        ((ByteArrayOutputStream) outputStream).reset();
      } else {
        dataToSign = ((DigestOutputStream) outputStream).digest();
        ((DigestOutputStream) outputStream).reset();
      }

      return cryptService.getIdentity(identityId).sign(mechanism, null, dataToSign);
    }
  } // method ECDSA

  // CHECKSTYLE:SKIP
  static class EdDSA extends P11ContentSigner {

    private final ByteArrayOutputStream outputStream;

    private final long mechanism;

    EdDSA(P11CryptService cryptService, P11IdentityId identityId, SignAlgo sigAlgo)
        throws XiSecurityException, P11TokenException {
      super(cryptService, identityId, sigAlgo);

      if (SignAlgo.ED25519 != sigAlgo) {
        throw new XiSecurityException("unsupproted signature algorithm " + sigAlgo);
      }

      mechanism = PKCS11Constants.CKM_EDDSA;
      P11Slot slot = cryptService.getSlot(identityId.getSlotId());
      if (!slot.supportsMechanism(mechanism)) {
        throw new XiSecurityException("unsupported signature algorithm " + sigAlgo);
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
        return cryptService.getIdentity(identityId).sign(mechanism, null, content);
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
      hashMechMap.put(SHA1, PKCS11Constants.CKM_SHA_1_HMAC);
      hashMechMap.put(SHA224, PKCS11Constants.CKM_SHA224_HMAC);
      hashMechMap.put(SHA256, PKCS11Constants.CKM_SHA256_HMAC);
      hashMechMap.put(SHA384, PKCS11Constants.CKM_SHA384_HMAC);
      hashMechMap.put(SHA512, PKCS11Constants.CKM_SHA512_HMAC);
      hashMechMap.put(SHA3_224, PKCS11Constants.CKM_SHA3_224_HMAC);
      hashMechMap.put(SHA3_256, PKCS11Constants.CKM_SHA3_256_HMAC);
      hashMechMap.put(SHA3_384, PKCS11Constants.CKM_SHA3_384_HMAC);
      hashMechMap.put(SHA3_512, PKCS11Constants.CKM_SHA3_512_HMAC);
    } // method static

    Mac(P11CryptService cryptService, P11IdentityId identityId,
        SignAlgo sigAlgo)
            throws XiSecurityException, P11TokenException {
      super(cryptService, identityId, sigAlgo);

      HashAlgo hashAlgo = sigAlgo.getHashAlgo();
      Long mech = hashMechMap.get(hashAlgo);
      if (mech == null) {
        throw new XiSecurityException("Unsupported signature algorithm " + sigAlgo);
      }

      this.mechanism = mech;
      P11Slot slot = cryptService.getSlot(identityId.getSlotId());
      if (slot.supportsMechanism(mechanism)) {
        throw new XiSecurityException("unsupported MAC algorithm " + sigAlgo);
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
        return cryptService.getIdentity(identityId).sign(mechanism, null, dataToSign);
      } catch (P11TokenException ex) {
        LogUtil.warn(LOG, ex);
        throw new RuntimeCryptoException("P11TokenException: " + ex.getMessage());
      } catch (Throwable th) {
        LogUtil.warn(LOG, th);
        throw new RuntimeCryptoException(th.getClass().getName() + ": " + th.getMessage());
      }
    }

  } // class Mac

  // CHECKSTYLE:SKIP
  static class RSA extends P11ContentSigner {

    private static final Map<HashAlgo, Long> hashMechMap = new HashMap<>();

    private final long mechanism;

    private final OutputStream outputStream;

    private final byte[] digestPkcsPrefix;

    private final int modulusBitLen;

    static {
      hashMechMap.put(SHA1, PKCS11Constants.CKM_SHA1_RSA_PKCS);
      hashMechMap.put(SHA224, PKCS11Constants.CKM_SHA224_RSA_PKCS);
      hashMechMap.put(SHA256, PKCS11Constants.CKM_SHA256_RSA_PKCS);
      hashMechMap.put(SHA384, PKCS11Constants.CKM_SHA384_RSA_PKCS);
      hashMechMap.put(SHA512, PKCS11Constants.CKM_SHA512_RSA_PKCS);
      hashMechMap.put(SHA3_224, PKCS11Constants.CKM_SHA3_224_RSA_PKCS);
      hashMechMap.put(SHA3_256, PKCS11Constants.CKM_SHA3_256_RSA_PKCS);
      hashMechMap.put(SHA3_384, PKCS11Constants.CKM_SHA3_384_RSA_PKCS);
      hashMechMap.put(SHA3_512, PKCS11Constants.CKM_SHA3_512_RSA_PKCS);
    } // method static

    RSA(P11CryptService cryptService, P11IdentityId identityId,
        SignAlgo sigAlgo)
            throws XiSecurityException, P11TokenException {
      super(cryptService, identityId, sigAlgo);

      if (!sigAlgo.isRSAPkcs1SigAlgo()) {
        throw new XiSecurityException("not an RSA PKCS#1 algorithm: " + sigAlgo);
      }

      HashAlgo hashAlgo = sigAlgo.getHashAlgo();
      Long mech = hashMechMap.get(hashAlgo);

      P11Slot slot = cryptService.getSlot(identityId.getSlotId());

      if (mech != null && slot.supportsMechanism(mech)) {
        mechanism = mech;
      } else if (slot.supportsMechanism(PKCS11Constants.CKM_RSA_PKCS)) {
        mechanism = PKCS11Constants.CKM_RSA_PKCS;
      } else if (slot.supportsMechanism(PKCS11Constants.CKM_RSA_X_509)) {
        mechanism = PKCS11Constants.CKM_RSA_X_509;
      } else {
        throw new XiSecurityException("unsupported signature algorithm " + sigAlgo);
      }

      if (mechanism == PKCS11Constants.CKM_RSA_PKCS
          || mechanism == PKCS11Constants.CKM_RSA_X_509) {
        this.digestPkcsPrefix = SignerUtil.getDigestPkcsPrefix(hashAlgo);
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else {
        this.digestPkcsPrefix = null;
        this.outputStream = new ByteArrayOutputStream();
      }

      RSAPublicKey rsaPubKey = (RSAPublicKey) cryptService.getIdentity(identityId).getPublicKey();
      this.modulusBitLen = rsaPubKey.getModulus().bitLength();
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
        if (mechanism == PKCS11Constants.CKM_RSA_X_509) {
          dataToSign = SignerUtil.EMSA_PKCS1_v1_5_encoding(dataToSign, modulusBitLen);
        }

        return cryptService.getIdentity(identityId).sign(mechanism, null, dataToSign);
      } catch (XiSecurityException | P11TokenException ex) {
        LogUtil.error(LOG, ex, "could not sign");
        throw new RuntimeCryptoException("SignerException: " + ex.getMessage());
      }
    } // method getSignature

  } // class RSA

  // CHECKSTYLE:SKIP
  static class RSAPSS extends P11ContentSigner {

    private static final Map<HashAlgo, Long> hashMechMap = new HashMap<>();

    static {
      hashMechMap.put(SHA1, PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS);
      hashMechMap.put(SHA224, PKCS11Constants.CKM_SHA224_RSA_PKCS_PSS);
      hashMechMap.put(SHA256, PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS);
      hashMechMap.put(SHA384, PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS);
      hashMechMap.put(SHA512, PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS);
      hashMechMap.put(SHA3_224, PKCS11Constants.CKM_SHA3_224_RSA_PKCS_PSS);
      hashMechMap.put(SHA3_256, PKCS11Constants.CKM_SHA3_256_RSA_PKCS_PSS);
      hashMechMap.put(SHA3_384, PKCS11Constants.CKM_SHA3_384_RSA_PKCS_PSS);
      hashMechMap.put(SHA3_512, PKCS11Constants.CKM_SHA3_512_RSA_PKCS_PSS);
    } // method static

    private final long mechanism;

    private final P11Params.P11RSAPkcsPssParams parameters;

    private final OutputStream outputStream;

    RSAPSS(P11CryptService cryptService, P11IdentityId identityId,
        SignAlgo sigAlgo, SecureRandom random)
        throws XiSecurityException, P11TokenException {
      super(cryptService, identityId, sigAlgo);
      if (!sigAlgo.isRSAPSSSigAlgo()) {
        throw new XiSecurityException("not an RSA PSS algorithm: " + sigAlgo);
      }

      notNull(random, "random");
      HashAlgo hashAlgo = sigAlgo.getHashAlgo();

      P11Slot slot = cryptService.getSlot(identityId.getSlotId());

      Long mech = hashMechMap.get(hashAlgo);
      if (mech != null && slot.supportsMechanism(mech)) {
        this.mechanism = mech;
        this.parameters = new P11Params.P11RSAPkcsPssParams(hashAlgo);
        this.outputStream = new ByteArrayOutputStream();
      } else if (!sigAlgo.getHashAlgo().isShake()
          && slot.supportsMechanism(PKCS11Constants.CKM_RSA_PKCS_PSS)) {
        this.mechanism = PKCS11Constants.CKM_RSA_PKCS_PSS;
        this.parameters = new P11Params.P11RSAPkcsPssParams(hashAlgo);
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else if (slot.supportsMechanism(PKCS11Constants.CKM_RSA_X_509)) {
        this.mechanism = PKCS11Constants.CKM_RSA_X_509;
        this.parameters = null;
        AsymmetricBlockCipher cipher = new P11PlainRSASigner();
        P11RSAKeyParameter keyParam;
        try {
          keyParam = P11RSAKeyParameter.getInstance(cryptService, identityId);
        } catch (InvalidKeyException ex) {
          throw new XiSecurityException(ex.getMessage(), ex);
        }
        Signer pssSigner = SignerUtil.createPSSRSASigner(sigAlgo, cipher);
        pssSigner.init(true, new ParametersWithRandom(keyParam, random));
        this.outputStream = new SignerOutputStream(pssSigner);
      } else {
        throw new XiSecurityException("unsupported signature algorithm " + sigAlgo);
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
        return cryptService.getIdentity(identityId).sign(mechanism, parameters, dataToSign);
      } catch (P11TokenException ex) {
        LogUtil.warn(LOG, ex, "could not sign");
        throw new RuntimeCryptoException("SignerException: " + ex.getMessage());
      }

    } // method getSignature

  } // class RSAPSS

  // CHECKSTYLE:SKIP
  static class SM2 extends P11ContentSigner {

    private static final Map<HashAlgo, Long> hashMechMap = new HashMap<>();

    private final long mechanism;

    private final OutputStream outputStream;

    // CHECKSTYLE:SKIP
    private final byte[] z;

    static {
      hashMechMap.put(SM3, PKCS11Constants.CKM_VENDOR_SM2_SM3);
    }

    SM2(P11CryptService cryptService, P11IdentityId identityId,
        SignAlgo sigAlgo, ASN1ObjectIdentifier curveOid, BigInteger pubPointX,
        BigInteger pubPointY)
            throws XiSecurityException, P11TokenException {
      super(cryptService, identityId, sigAlgo);
      if (!sigAlgo.isSM2SigAlgo()) {
        throw new XiSecurityException("not an SM2 algorithm: " + sigAlgo);
      }

      P11Slot slot = cryptService.getSlot(identityId.getSlotId());

      HashAlgo hashAlgo = sigAlgo.getHashAlgo();
      Long mech = hashMechMap.get(hashAlgo);
      if (mech != null && slot.supportsMechanism(mech)) {
        this.mechanism = mech;
        this.z = null; // not required
        this.outputStream = new ByteArrayOutputStream();
      } else if (slot.supportsMechanism(PKCS11Constants.CKM_VENDOR_SM2)) {
        this.mechanism = PKCS11Constants.CKM_VENDOR_SM2;
        this.z = GMUtil.getSM2Z(curveOid, pubPointX, pubPointY);
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else {
        throw new XiSecurityException("unsupported signature algorithm " + sigAlgo);
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

    private byte[] getPlainSignature()
        throws XiSecurityException, P11TokenException {
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

      return cryptService.getIdentity(identityId).sign(mechanism, params, dataToSign);
    }
  } // class SM2

}
