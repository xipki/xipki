// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.RuntimeCryptoException;
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
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;
import static org.xipki.security.SignAlgo.*;
import static org.xipki.util.Args.notNull;

/**
 * PKCS#11 {@link XiContentSigner}.
 *
 * @author Lijun Liao (xipki)
 *
 */
abstract class P11ContentSigner implements XiContentSigner {

  private static final Logger LOG = LoggerFactory.getLogger(P11ContentSigner.class);

  protected final P11Key identity;

  protected final SignAlgo signAlgo;

  protected final byte[] encodedAlgorithmIdentifier;

  private P11ContentSigner(P11Key identity, SignAlgo signAlgo) throws XiSecurityException {
    this.identity = notNull(identity, "identity");
    this.signAlgo = notNull(signAlgo, "signAlgo");
    try {
      this.encodedAlgorithmIdentifier = signAlgo.getAlgorithmIdentifier().getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }
  }

  static P11ContentSigner newInstance(P11Key identity, SignAlgo signAlgo,
                                      SecureRandom random, PublicKey publicKey)
      throws XiSecurityException {
    long keyType = identity.getKeyType();
    if (keyType == CKK_RSA) {
      if (signAlgo.isRSAPSSSigAlgo()) {
        return new RSAPSS(identity, signAlgo, random);
      } else {
        return new RSAPkcs1v1_5(identity, signAlgo);
      }
    } else if (keyType == CKK_EC || keyType == CKK_VENDOR_SM2) {
      boolean isSm2p256v1 = (keyType == CKK_VENDOR_SM2) || GMObjectIdentifiers.sm2p256v1.equals(identity.getEcParams());

     if (isSm2p256v1) {
       if (publicKey == null) {
         publicKey = identity.getPublicKey();
       }

       if (publicKey == null) {
         throw new XiSecurityException("SM2 signer needs public key, but could not get anyone.");
       }

       java.security.spec.ECPoint w = ((ECPublicKey) publicKey).getW();
       BigInteger wx = w.getAffineX();
       BigInteger wy = w.getAffineY();

       return new SM2(identity, signAlgo, GMObjectIdentifiers.sm2p256v1, wx, wy);
     } else {
       return new ECDSA(identity, signAlgo);
     }
    } else if (keyType == CKK_DSA) {
      return new DSA(identity, signAlgo);
    } else if (keyType == CKK_EC_EDWARDS) {
      return new EdDSA(identity, signAlgo);
    } else if (keyType == CKK_AES || keyType == CKK_GENERIC_SECRET) {
      return new Mac(identity, signAlgo);
    } else {
      throw new XiSecurityException("unsupported key type " + ckkCodeToName(keyType));
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

  private static class DSA extends P11ContentSigner {

    private static final Map<SignAlgo, Long> algoMechMap = new HashMap<>();

    private final OutputStream outputStream;

    private final long mechanism;

    static {
      algoMechMap.put(DSA_SHA1,     CKM_DSA_SHA1);
      algoMechMap.put(DSA_SHA224,   CKM_DSA_SHA224);
      algoMechMap.put(DSA_SHA256,   CKM_DSA_SHA256);
      algoMechMap.put(DSA_SHA384,   CKM_DSA_SHA384);
      algoMechMap.put(DSA_SHA512,   CKM_DSA_SHA512);
      algoMechMap.put(DSA_SHA3_224, CKM_DSA_SHA3_224);
      algoMechMap.put(DSA_SHA3_256, CKM_DSA_SHA3_256);
      algoMechMap.put(DSA_SHA3_384, CKM_DSA_SHA3_384);
      algoMechMap.put(DSA_SHA3_512, CKM_DSA_SHA3_512);
    } // method static

    DSA(P11Key identity, SignAlgo signAlgo) throws XiSecurityException {
      super(identity, signAlgo);

      if (!signAlgo.isDSASigAlgo()) {
        throw new XiSecurityException("not a DSA algorithm: " + signAlgo);
      }

      Long mech = algoMechMap.get(signAlgo);
      if (mech == null) {
        throw new XiSecurityException("unsupported signature algorithm " + signAlgo);
      }

      if (identity.supportsSign(CKM_DSA)) {
        mechanism = CKM_DSA;
        outputStream = new DigestOutputStream(signAlgo.getHashAlgo().createDigest());
      } else if (identity.supportsSign(mech)) {
        mechanism = mech;
        outputStream = new ByteArrayOutputStream();
      } else {
        throw new XiSecurityException("signature algorithm " + signAlgo + " is not supported by the device");
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

  private static class ECDSA extends P11ContentSigner {

    private static final Map<SignAlgo, Long> algoMechMap = new HashMap<>();

    private final OutputStream outputStream;

    private final long mechanism;

    static {
      algoMechMap.put(ECDSA_SHA1,   CKM_ECDSA_SHA1);
      algoMechMap.put(ECDSA_SHA224, CKM_ECDSA_SHA224);
      algoMechMap.put(ECDSA_SHA256, CKM_ECDSA_SHA256);
      algoMechMap.put(ECDSA_SHA384, CKM_ECDSA_SHA384);
      algoMechMap.put(ECDSA_SHA512, CKM_ECDSA_SHA512);
      algoMechMap.put(ECDSA_SHA3_224, CKM_ECDSA_SHA3_224);
      algoMechMap.put(ECDSA_SHA3_256, CKM_ECDSA_SHA3_256);
      algoMechMap.put(ECDSA_SHA3_384, CKM_ECDSA_SHA3_384);
      algoMechMap.put(ECDSA_SHA3_512, CKM_ECDSA_SHA3_512);
    } // method static

    ECDSA(P11Key identity, SignAlgo signAlgo) throws XiSecurityException {
      super(identity, signAlgo);
      if (!signAlgo.isECDSASigAlgo()) {
        throw new XiSecurityException("not an ECDSA algorithm: " + signAlgo);
      }

      Long mech = algoMechMap.get(signAlgo);
      if (mech == null) {
        throw new XiSecurityException("unsupported signature algorithm " + signAlgo);
      }

      if (identity.supportsSign(CKM_ECDSA)) {
        mechanism = CKM_ECDSA;
        this.outputStream = new DigestOutputStream(signAlgo.getHashAlgo().createDigest());
      } else if (identity.supportsSign(mech)) {
        mechanism = mech;
        this.outputStream = new ByteArrayOutputStream();
      } else {
        throw new XiSecurityException("signature algorithm " + signAlgo + " is not supported by the device");
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

  private static class EdDSA extends P11ContentSigner {

    private final ByteArrayOutputStream outputStream;

    private final long mechanism;

    EdDSA(P11Key identity, SignAlgo signAlgo) throws XiSecurityException {
      super(identity, signAlgo);

      if (SignAlgo.ED25519 != signAlgo) {
        throw new XiSecurityException("unsupported signature algorithm " + signAlgo);
      }

      mechanism = CKM_EDDSA;
      if (!identity.supportsSign(mechanism)) {
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

  private static class Mac extends P11ContentSigner {

    private static final Map<SignAlgo, Long> algoMechMap = new HashMap<>();

    private final long mechanism;

    private final ByteArrayOutputStream outputStream;

    static {
      algoMechMap.put(HMAC_SHA1,   CKM_SHA_1_HMAC);
      algoMechMap.put(HMAC_SHA224, CKM_SHA224_HMAC);
      algoMechMap.put(HMAC_SHA256, CKM_SHA256_HMAC);
      algoMechMap.put(HMAC_SHA384, CKM_SHA384_HMAC);
      algoMechMap.put(HMAC_SHA512, CKM_SHA512_HMAC);
      algoMechMap.put(HMAC_SHA3_224, CKM_SHA3_224_HMAC);
      algoMechMap.put(HMAC_SHA3_256, CKM_SHA3_256_HMAC);
      algoMechMap.put(HMAC_SHA3_384, CKM_SHA3_384_HMAC);
      algoMechMap.put(HMAC_SHA3_512, CKM_SHA3_512_HMAC);
    } // method static

    Mac(P11Key identity, SignAlgo signAlgo) throws XiSecurityException {
      super(identity, signAlgo);

      Long mech = algoMechMap.get(signAlgo);
      if (mech == null) {
        throw new XiSecurityException("Unsupported signature algorithm " + signAlgo);
      }

      this.mechanism = mech;
      if (identity.supportsSign(mechanism)) {
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

  private static class RSAPkcs1v1_5 extends P11ContentSigner {

    private static final Map<SignAlgo, Long> algoMechMap = new HashMap<>();

    private final long mechanism;

    private final OutputStream outputStream;

    private final byte[] digestPkcsPrefix;

    private final int modulusBitLen;

    static {
      algoMechMap.put(RSA_SHA1,   CKM_SHA1_RSA_PKCS);
      algoMechMap.put(RSA_SHA224, CKM_SHA224_RSA_PKCS);
      algoMechMap.put(RSA_SHA256, CKM_SHA256_RSA_PKCS);
      algoMechMap.put(RSA_SHA384, CKM_SHA384_RSA_PKCS);
      algoMechMap.put(RSA_SHA512, CKM_SHA512_RSA_PKCS);
      algoMechMap.put(RSA_SHA3_224, CKM_SHA3_224_RSA_PKCS);
      algoMechMap.put(RSA_SHA3_256, CKM_SHA3_256_RSA_PKCS);
      algoMechMap.put(RSA_SHA3_384, CKM_SHA3_384_RSA_PKCS);
      algoMechMap.put(RSA_SHA3_512, CKM_SHA3_512_RSA_PKCS);
    } // method static

    RSAPkcs1v1_5(P11Key identity, SignAlgo signAlgo) throws XiSecurityException {
      super(identity, signAlgo);

      if (!signAlgo.isRSAPkcs1SigAlgo()) {
        throw new XiSecurityException("not an RSA PKCS#1 algorithm: " + signAlgo);
      }

      Long mech = algoMechMap.get(signAlgo);
      if (mech == null) {
        throw new XiSecurityException("unsupported signature algorithm " + signAlgo);
      }

      if (identity.supportsSign(CKM_RSA_PKCS)) {
        mechanism = CKM_RSA_PKCS;
      } else if (identity.supportsSign(CKM_RSA_X_509)) {
        mechanism = CKM_RSA_X_509;
      } else if (identity.supportsSign(mech)) {
        mechanism = mech;
      } else {
        throw new XiSecurityException("signature algorithm " + signAlgo + " is not supported by the device");
      }

      if (mechanism == CKM_RSA_PKCS || mechanism == CKM_RSA_X_509) {
        this.digestPkcsPrefix = PKCS1Util.getDigestPkcsPrefix(signAlgo.getHashAlgo());
        this.outputStream = new DigestOutputStream(signAlgo.getHashAlgo().createDigest());
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

  private static class RSAPSS extends P11ContentSigner {

    private static final Map<SignAlgo, Long> algoMechMap = new HashMap<>();

    static {
      algoMechMap.put(RSAPSS_SHA1,   CKM_SHA1_RSA_PKCS_PSS);
      algoMechMap.put(RSAPSS_SHA224, CKM_SHA224_RSA_PKCS_PSS);
      algoMechMap.put(RSAPSS_SHA256, CKM_SHA256_RSA_PKCS_PSS);
      algoMechMap.put(RSAPSS_SHA384, CKM_SHA384_RSA_PKCS_PSS);
      algoMechMap.put(RSAPSS_SHA512, CKM_SHA512_RSA_PKCS_PSS);
      algoMechMap.put(RSAPSS_SHA3_224, CKM_SHA3_224_RSA_PKCS_PSS);
      algoMechMap.put(RSAPSS_SHA3_256, CKM_SHA3_256_RSA_PKCS_PSS);
      algoMechMap.put(RSAPSS_SHA3_384, CKM_SHA3_384_RSA_PKCS_PSS);
      algoMechMap.put(RSAPSS_SHA3_512, CKM_SHA3_512_RSA_PKCS_PSS);
    } // method static

    private final long mechanism;

    private final P11Params.P11RSAPkcsPssParams parameters;

    private final OutputStream outputStream;

    private final SecureRandom random;

    RSAPSS(P11Key identity, SignAlgo signAlgo, SecureRandom random) throws XiSecurityException {
      super(identity, signAlgo);
      if (!signAlgo.isRSAPSSSigAlgo()) {
        throw new XiSecurityException("not an RSA PSS algorithm: " + signAlgo);
      }

      this.random = notNull(random, "random");
      HashAlgo hashAlgo = signAlgo.getHashAlgo();

      Long mech = algoMechMap.get(signAlgo);
      if (mech == null) {
        throw new XiSecurityException("unsupported signature algorithm " + signAlgo);
      }

      boolean usePss = signAlgo.isRSAPSSMGF1SigAlgo() && identity.supportsSign(CKM_RSA_PKCS_PSS);
      if (usePss) {
        switch (signAlgo.getHashAlgo()) {
          case SHA1:
          case SHA224:
          case SHA256:
          case SHA384:
          case SHA512:
            break;
          default:
            usePss = false;
            break;
        }
      }

      if (usePss) {
        this.mechanism = CKM_RSA_PKCS_PSS;
        this.parameters = new P11Params.P11RSAPkcsPssParams(hashAlgo);
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else if (identity.supportsSign(CKM_RSA_X_509)) {
        this.mechanism = CKM_RSA_X_509;
        this.parameters = null;
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else if (identity.supportsSign(mech)) {
        this.mechanism = mech;
        this.parameters = new P11Params.P11RSAPkcsPssParams(hashAlgo);
        this.outputStream = new ByteArrayOutputStream();
      } else {
        throw new XiSecurityException("signature algorithm " + signAlgo + " is not supported by the device");
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
        if (mechanism == CKM_RSA_X_509) {
          HashAlgo hash = signAlgo.getHashAlgo();
          byte[] hashValue = ((DigestOutputStream) outputStream).digest();
          byte[] encodedHashValue;
          try {
            encodedHashValue = PKCS1Util.EMSA_PSS_ENCODE(hash, hashValue, hash,
                hash.getLength(), identity.getRsaModulus().bitLength(), random);
          } catch (XiSecurityException ex) {
            throw new TokenException("XiSecurityException: " + ex.getMessage(), ex);
          }
          return identity.sign(mechanism, parameters, encodedHashValue);
        } else {
          byte[] dataToSign;
          if (outputStream instanceof ByteArrayOutputStream) {
            dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
          } else {
            dataToSign = ((DigestOutputStream) outputStream).digest();
          }

          return identity.sign(mechanism, parameters, dataToSign);
        }
      } catch (TokenException ex) {
        LogUtil.warn(LOG, ex, "could not sign");
        throw new RuntimeCryptoException("SignerException: " + ex.getMessage());
      }

    } // method getSignature

  } // class RSAPSS

  private static class SM2 extends P11ContentSigner {

    private static final Map<SignAlgo, Long> algoMechMap = new HashMap<>();

    private final long mechanism;

    private final OutputStream outputStream;

    private final byte[] z;

    static {
      algoMechMap.put(SM2_SM3, CKM_VENDOR_SM2_SM3);
    }

    SM2(P11Key identity, SignAlgo signAlgo, ASN1ObjectIdentifier curveOid,
        BigInteger pubPointX, BigInteger pubPointY) throws XiSecurityException {
      super(identity, signAlgo);
      if (!signAlgo.isSM2SigAlgo()) {
        throw new XiSecurityException("not an SM2 algorithm: " + signAlgo);
      }

      HashAlgo hashAlgo = signAlgo.getHashAlgo();
      Long mech = algoMechMap.get(signAlgo);
      if (mech == null) {
        throw new XiSecurityException("unsupported signature algorithm " + signAlgo);
      }

      if (identity.supportsSign(CKM_VENDOR_SM2)) {
        this.mechanism = CKM_VENDOR_SM2;
        this.z = GMUtil.getSM2Z(curveOid, pubPointX, pubPointY);
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else if (identity.supportsSign(mech)) {
        this.mechanism = mech;
        this.z = null; // not required
        this.outputStream = new ByteArrayOutputStream();
      } else {
        throw new XiSecurityException("signature algorithm " + signAlgo + " is not supported by the device");
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
