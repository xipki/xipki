// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.operator.ContentSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.sign.Signer;
import org.xipki.security.util.DigestOutputStream;
import org.xipki.security.util.EcCurveEnum;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.PKCS1Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.asn1.Asn1Util;
import org.xipki.util.extra.misc.LogUtil;

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
import java.util.Optional;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;
import static org.xipki.security.SignAlgo.*;

/**
 * PKCS#11 {@link Signer}.
 *
 * @author Lijun Liao (xipki)
 */
abstract class P11Signer implements Signer {

  private static final Logger LOG = LoggerFactory.getLogger(P11Signer.class);

  protected final P11Key identity;

  protected final SignAlgo signAlgo;

  protected final byte[] encodedX509AlgId;

  private P11Signer(P11Key identity, SignAlgo signAlgo)
      throws XiSecurityException {
    this.identity = Args.notNull(identity, "identity");
    this.signAlgo = Args.notNull(signAlgo, "signAlgo");
    try {
      this.encodedX509AlgId = signAlgo.algorithmIdentifier().getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }
  }

  static P11Signer newInstance(
      P11Key identity, SignAlgo signAlgo, SecureRandom random,
      PublicKey publicKey) throws XiSecurityException {
    return newInstance(identity, signAlgo, random, publicKey, null);
  }

  static P11Signer newInstance(
      P11Key identity, SignAlgo signAlgo, SecureRandom random,
      PublicKey publicKey, byte[] context) throws XiSecurityException {
    long keyType = identity.key().id().getKeyType();
    if (keyType == CKK_RSA) {
      return signAlgo.isRSAPSSSigAlgo() ? new RSAPSS(identity, signAlgo, random)
          : new RSAPkcs1v1_5(identity, signAlgo);
    } else if (keyType == CKK_EC || keyType == CKK_VENDOR_SM2) {
      boolean isSm2p256v1 = (keyType == CKK_VENDOR_SM2)
          || EcCurveEnum.SM2P256V1 == identity.ecParams();

     if (isSm2p256v1) {
       if (publicKey == null) {
         publicKey = Optional.ofNullable(identity.publicKey())
             .orElseThrow(() -> new XiSecurityException(
                 "SM2 signer needs public key, but could not get anyone."));
       }

       java.security.spec.ECPoint w = ((ECPublicKey) publicKey).getW();
       return new SM2(identity, signAlgo, w.getAffineX(), w.getAffineY());
     } else {
       return new ECDSA(identity, signAlgo);
     }
    } else if (keyType == CKK_EC_EDWARDS) {
      EcCurveEnum curve = identity.ecParams();
      boolean match = (curve == EcCurveEnum.ED25519) ? signAlgo == ED25519
          : signAlgo == ED448;

      if (!match) {
        throw new XiSecurityException(
            "key is not suitable for the sign algo " + signAlgo);
      }

      return new EdDSA(identity, signAlgo);
    } else if (keyType == CKK_ML_DSA) {
      Long variant = identity.key().pqcVariant();
      boolean match = false;
      if (variant != null) {
        match = (signAlgo == MLDSA44) ? variant == CKP_ML_DSA_44
              : (signAlgo == MLDSA65) ? variant == CKP_ML_DSA_65
              :  signAlgo == MLDSA87 && variant == CKP_ML_DSA_87;
      }

      if (!match) {
        throw new XiSecurityException(
            "key is not suitable for the sign algo " + signAlgo);
      }

      return new MLDSA(identity, signAlgo, context);
    } else if (keyType == CKK_AES || keyType == CKK_GENERIC_SECRET) {
      return new Mac(identity, signAlgo);
    } else {
      throw new XiSecurityException(
          "unsupported key type " + ckkCodeToName(keyType));
    }
  }

  @Override
  public final byte[] getEncodedX509AlgId() {
    return Arrays.copyOf(encodedX509AlgId, encodedX509AlgId.length);
  }

  private static class ECDSA extends P11Signer {

    private static final Map<SignAlgo, Long> algoMechMap = new HashMap<>();

    private final OutputStream outputStream;

    private final long mechanism;

    private final MyX509Signer x509Signer;

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

      long mech = Optional.ofNullable(algoMechMap.get(signAlgo))
          .orElseThrow(() -> new XiSecurityException(
              "unsupported signature algorithm " + signAlgo));

      if (identity.supportsSign(CKM_ECDSA)) {
        mechanism = CKM_ECDSA;
        this.outputStream = new DigestOutputStream(
            signAlgo.hashAlgo().createDigest());
      } else if (identity.supportsSign(mech)) {
        mechanism = mech;
        this.outputStream = new ByteArrayOutputStream();
      } else {
        throw new XiSecurityException("signature algorithm " + signAlgo
            + " is not supported by the device");
      }

      this.x509Signer = new MyX509Signer();
    } // method constructor

    @Override
    public ContentSigner x509Signer() {
      return x509Signer;
    }

    private byte[] getPlainSignature() throws TokenException {
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

    class MyX509Signer implements ContentSigner {

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return signAlgo.algorithmIdentifier();
      }

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
          return dsaSigPlainToX962(getPlainSignature());
        } catch (XiSecurityException ex) {
          LogUtil.warn(LOG, ex);
          throw new RuntimeCryptoException(
              "XiSecurityException: " + ex.getMessage());
        } catch (Throwable th) {
          LogUtil.warn(LOG, th);
          throw new RuntimeCryptoException(
              th.getClass().getName() + ": " + th.getMessage());
        }
      }

    }

  } // method ECDSA

  private static class EdDSA extends P11Signer {

    private static final P11Params.P11EddsaParams ed448Params =
        new P11Params.P11EddsaParams(false, null);

    private final long mechanism;

    private final ByteArrayOutputStream outputStream =
        new ByteArrayOutputStream();

    private final MyX509Signer x509Signer;

    EdDSA(P11Key identity, SignAlgo signAlgo) throws XiSecurityException {
      super(identity, signAlgo);

      if (SignAlgo.ED25519 != signAlgo && ED448 != signAlgo) {
        throw new XiSecurityException(
            "unsupported signature algorithm " + signAlgo);
      }

      mechanism = CKM_EDDSA;
      if (!identity.supportsSign(mechanism)) {
        throw new XiSecurityException(
            "unsupported signature algorithm " + signAlgo);
      }

      this.x509Signer = new MyX509Signer();
    }

    @Override
    public ContentSigner x509Signer() {
      return x509Signer;
    }

    class MyX509Signer implements ContentSigner {

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return signAlgo.algorithmIdentifier();
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
          P11Params params = null;
          if (signAlgo == ED448) {
           params = ed448Params;
          }

          return identity.sign(mechanism, params, content);
        } catch (Throwable th) {
          LogUtil.warn(LOG, th);
          throw new RuntimeCryptoException(
              th.getClass().getName() + ": " + th.getMessage());
        }
      }
    }

  } // class EdDSA

  private static class MLDSA extends P11Signer {

    private final byte[] context;
    private final long mechanism;
    private final ByteArrayOutputStream outputStream =
        new ByteArrayOutputStream();
    private final MyX509Signer x509Signer;

    MLDSA(P11Key identity, SignAlgo signAlgo) throws XiSecurityException {
      this(identity, signAlgo, null);
    }

    MLDSA(P11Key identity, SignAlgo signAlgo, byte[] context)
        throws XiSecurityException {
      super(identity, signAlgo);
      this.context = context == null ? new byte[0] : context.clone();

      this.mechanism = CKM_ML_DSA;
      if (!identity.supportsSign(this.mechanism)) {
        throw new XiSecurityException(
            "unsupported signature algorithm " + signAlgo);
      }

      this.x509Signer = new MyX509Signer();
    }

    @Override
    public ContentSigner x509Signer() {
      return x509Signer;
    }

    class MyX509Signer implements ContentSigner {

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return signAlgo.algorithmIdentifier();
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
          P11Params params = (content.length == 0) ? null
              : new P11Params.P11SignAdditionalContext(context);
          return identity.sign(mechanism, params, content);
        } catch (Throwable th) {
          LogUtil.warn(LOG, th);
          throw new RuntimeCryptoException(
              th.getClass().getName() + ": " + th.getMessage());
        }
      }
    }

  } // class MLDSA

  private static class Mac extends P11Signer {

    private static final Map<SignAlgo, Long> algoMechMap = new HashMap<>();

    private final long mechanism;

    private final ByteArrayOutputStream outputStream =
        new ByteArrayOutputStream();

    private final MyX509Signer x509Signer;

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

      this.mechanism = Optional.ofNullable(algoMechMap.get(signAlgo))
          .orElseThrow(() -> new XiSecurityException(
              "Unsupported MAC algorithm " + signAlgo));

      if (identity.supportsSign(mechanism)) {
        throw new XiSecurityException("unsupported MAC algorithm " + signAlgo);
      }

      this.x509Signer = new MyX509Signer();
    } // constructor

    @Override
    public ContentSigner x509Signer() {
      return x509Signer;
    }

    private class MyX509Signer implements ContentSigner {

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return signAlgo.algorithmIdentifier();
      }

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
          throw new RuntimeCryptoException(
              "TokenException: " + ex.getMessage());
        } catch (Throwable th) {
          LogUtil.warn(LOG, th);
          throw new RuntimeCryptoException(
              th.getClass().getName() + ": " + th.getMessage());
        }
      }

    }

  } // class Mac

  private static class RSAPkcs1v1_5 extends P11Signer {

    private static final Map<SignAlgo, Long> algoMechMap = new HashMap<>();

    private final long mechanism;

    private final byte[] digestPkcsPrefix;

    private final int modulusBitLen;

    private final OutputStream outputStream;

    private final MyX509Signer x509Signer;

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

    RSAPkcs1v1_5(P11Key identity, SignAlgo signAlgo)
        throws XiSecurityException {
      super(identity, signAlgo);

      if (!signAlgo.isRSAPkcs1SigAlgo()) {
        throw new XiSecurityException(
            "not an RSA PKCS#1 algorithm: " + signAlgo);
      }

      long mech = Optional.ofNullable(algoMechMap.get(signAlgo))
          .orElseThrow(() -> new XiSecurityException(
              "unsupported signature algorithm " + signAlgo));

      if (identity.supportsSign(CKM_RSA_PKCS)) {
        mechanism = CKM_RSA_PKCS;
      } else if (identity.supportsSign(CKM_RSA_X_509)) {
        mechanism = CKM_RSA_X_509;
      } else if (identity.supportsSign(mech)) {
        mechanism = mech;
      } else {
        throw new XiSecurityException("signature algorithm " + signAlgo
            + " is not supported by the device");
      }

      if (mechanism == CKM_RSA_PKCS || mechanism == CKM_RSA_X_509) {
        this.digestPkcsPrefix = PKCS1Util.getDigestPkcsPrefix(
            signAlgo.hashAlgo());
      } else {
        this.digestPkcsPrefix = null;
      }

      this.modulusBitLen = identity.key().rsaModulus().bitLength();
      if (mechanism == CKM_RSA_PKCS || mechanism == CKM_RSA_X_509) {
        this.outputStream = new DigestOutputStream(
            signAlgo.hashAlgo().createDigest());
      } else {
        this.outputStream = new ByteArrayOutputStream();
      }
      this.x509Signer = new MyX509Signer();
    } // constructor

    @Override
    public ContentSigner x509Signer() {
      return x509Signer;
    }

    private class MyX509Signer implements ContentSigner {

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return signAlgo.algorithmIdentifier();
      }

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
          System.arraycopy(digestPkcsPrefix, 0, dataToSign,
              0, digestPkcsPrefix.length);
          System.arraycopy(hashValue, 0, dataToSign,
              digestPkcsPrefix.length, hashValue.length);
        }

        try {
          if (mechanism == CKM_RSA_X_509) {
            dataToSign = PKCS1Util.EMSA_PKCS1_V1_5_ENCODE(
                dataToSign, modulusBitLen);
          }

          return identity.sign(mechanism, null, dataToSign);
        } catch (XiSecurityException | TokenException ex) {
          LogUtil.error(LOG, ex, "could not sign");
          throw new RuntimeCryptoException(
              "SignerException: " + ex.getMessage());
        }
      } // method getSignature
    }

  } // class RSA

  private static class RSAPSS extends P11Signer {

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

    private final SecureRandom random;

    private final OutputStream outputStream;

    private final MyX509Signer x509Signer;

    RSAPSS(P11Key identity, SignAlgo signAlgo, SecureRandom random)
        throws XiSecurityException {
      super(identity, signAlgo);
      if (!signAlgo.isRSAPSSSigAlgo()) {
        throw new XiSecurityException("not an RSA PSS algorithm: " + signAlgo);
      }

      this.random = Args.notNull(random, "random");
      HashAlgo hashAlgo = signAlgo.hashAlgo();

      long mech = Optional.ofNullable(algoMechMap.get(signAlgo))
          .orElseThrow(() -> new XiSecurityException(
              "unsupported signature algorithm " + signAlgo));

      boolean usePss = signAlgo.isRSAPSSMGF1SigAlgo()
          && identity.supportsSign(CKM_RSA_PKCS_PSS);
      if (usePss) {
        switch (hashAlgo) {
          case SHA1:
          case SHA224:
          case SHA256:
          case SHA384:
          case SHA512:
            break;
          default:
            usePss = false;
        }
      }

      if (usePss) {
        this.mechanism = CKM_RSA_PKCS_PSS;
        this.parameters = new P11Params.P11RSAPkcsPssParams(hashAlgo);
      } else if (identity.supportsSign(CKM_RSA_X_509)) {
        this.mechanism = CKM_RSA_X_509;
        this.parameters = null;
      } else if (identity.supportsSign(mech)) {
        this.mechanism = mech;
        this.parameters = new P11Params.P11RSAPkcsPssParams(hashAlgo);
      } else {
        throw new XiSecurityException("signature algorithm " + signAlgo
            + " is not supported by the device");
      }

      if (usePss) {
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else if (identity.supportsSign(CKM_RSA_X_509)) {
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else { // if (identity.supportsSign(mech)) {
        this.outputStream = new ByteArrayOutputStream();
      }
      this.x509Signer = new MyX509Signer();
    } // constructor

    @Override
    public ContentSigner x509Signer() {
      return x509Signer;
    }

    private class MyX509Signer implements ContentSigner {

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return signAlgo.algorithmIdentifier();
      }

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
            HashAlgo hash = signAlgo.hashAlgo();
            byte[] hashValue = ((DigestOutputStream) outputStream).digest();
            byte[] encodedHashValue;
            try {
              encodedHashValue = PKCS1Util.EMSA_PSS_ENCODE(hash, hashValue,
                  hash, hash.length(), identity.key().rsaModulus().bitLength(),
                  random);
            } catch (XiSecurityException ex) {
              throw new TokenException(
                  "XiSecurityException: " + ex.getMessage(), ex);
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
          throw new RuntimeCryptoException(
              "SignerException: " + ex.getMessage());
        }

      } // method getSignature
    }

  } // class RSAPSS

  private static class SM2 extends P11Signer {

    private static final Map<SignAlgo, Long> algoMechMap = new HashMap<>();

    private final long mechanism;

    private final OutputStream outputStream;

    private final byte[] z;

    private final MyX509Signer x509Signer;

    static {
      algoMechMap.put(SM2_SM3, CKM_VENDOR_SM2_SM3);
    }

    SM2(P11Key identity, SignAlgo signAlgo,
        BigInteger pubPointX, BigInteger pubPointY) throws XiSecurityException {
      super(identity, signAlgo);
      if (!signAlgo.isSM2SigAlgo()) {
        throw new XiSecurityException("not an SM2 algorithm: " + signAlgo);
      }

      HashAlgo hashAlgo = signAlgo.hashAlgo();
      long mech = Optional.ofNullable(algoMechMap.get(signAlgo))
          .orElseThrow(() -> new XiSecurityException(
              "unsupported signature algorithm " + signAlgo));

      if (identity.supportsSign(CKM_VENDOR_SM2)) {
        this.mechanism = CKM_VENDOR_SM2;
        this.z = KeyUtil.getSM2Z(null, pubPointX, pubPointY);
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else if (identity.supportsSign(mech)) {
        this.mechanism = mech;
        this.z = null; // not required
        this.outputStream = new ByteArrayOutputStream();
      } else {
        throw new XiSecurityException("signature algorithm " + signAlgo
            + " is not supported by the device");
      }

      this.x509Signer = new MyX509Signer();
    }

    @Override
    public ContentSigner x509Signer() {
      return x509Signer;
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

    private class MyX509Signer implements ContentSigner {

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return signAlgo.algorithmIdentifier();
      }

      @Override
      public OutputStream getOutputStream() {
        reset();
        return outputStream;
      }

      @Override
      public byte[] getSignature() {
        try {
          return dsaSigPlainToX962(getPlainSignature());
        } catch (XiSecurityException ex) {
          LogUtil.warn(LOG, ex);
          throw new RuntimeCryptoException(
              "XiSecurityException: " + ex.getMessage());
        } catch (Throwable th) {
          LogUtil.warn(LOG, th);
          throw new RuntimeCryptoException(
              th.getClass().getName() + ": " + th.getMessage());
        }
      }

    }

    private byte[] getPlainSignature() throws TokenException {
      byte[] dataToSign;
      if (outputStream instanceof ByteArrayOutputStream) {
        // dataToSign is the real message
        dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
      } else {
        // dataToSign is Hash(Z||Real Message)
        dataToSign = ((DigestOutputStream) outputStream).digest();
      }

      reset();

      return identity.sign(mechanism, null, dataToSign);
    }
  } // class SM2

  private static byte[] dsaSigPlainToX962(byte[] signature)
      throws XiSecurityException {
    byte[] x962Sig = Asn1Util.dsaSigPlainToX962(
        Args.notNull(signature, "signature"));

    if (Arrays.equals(x962Sig, signature)) {
      throw new XiSecurityException("signature is not correctly encoded.");
    }
    return x962Sig;
  }

}
