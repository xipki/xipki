/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.security.pkcs11.emulator;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.TimeUnit;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.HashAlgo;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.P11ByteArrayParams;
import org.xipki.security.pkcs11.P11EntityIdentifier;
import org.xipki.security.pkcs11.P11IVParams;
import org.xipki.security.pkcs11.P11Identity;
import org.xipki.security.pkcs11.P11Params;
import org.xipki.security.pkcs11.P11RSAPkcsPssParams;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.exception.P11TokenException;
import org.xipki.security.util.GMUtil;
import org.xipki.security.util.SignerUtil;
import org.xipki.util.ParamUtil;
import org.xipki.util.concurrent.ConcurrentBag;
import org.xipki.util.concurrent.ConcurrentBagEntry;

import iaik.pkcs.pkcs11.constants.Functions;
import iaik.pkcs.pkcs11.constants.PKCS11Constants;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class EmulatorP11Identity extends P11Identity {

  private static final Logger LOG = LoggerFactory.getLogger(EmulatorP11Identity.class);

  private final Key signingKey;

  private final ConcurrentBag<ConcurrentBagEntry<Cipher>> rsaCiphers = new ConcurrentBag<>();

  private final ConcurrentBag<ConcurrentBagEntry<Signature>> dsaSignatures =
      new ConcurrentBag<>();

  private final ConcurrentBag<ConcurrentBagEntry<SM2Signer>> sm2Signers = new ConcurrentBag<>();

  private final SecureRandom random;

  public EmulatorP11Identity(P11Slot slot, P11EntityIdentifier identityId,
      SecretKey signingKey, int maxSessions, SecureRandom random) {
    super(slot, identityId, 0);
    this.signingKey = ParamUtil.requireNonNull("signingKey", signingKey);
    this.random = ParamUtil.requireNonNull("random", random);
  } // constructor

  public EmulatorP11Identity(P11Slot slot, P11EntityIdentifier identityId, PrivateKey privateKey,
      PublicKey publicKey, X509Certificate[] certificateChain, int maxSessions,
      SecureRandom random)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
    super(slot, identityId, publicKey, certificateChain);
    this.signingKey = ParamUtil.requireNonNull("privateKey", privateKey);
    this.random = ParamUtil.requireNonNull("random", random);

    if (this.publicKey instanceof RSAPublicKey) {
      String providerName = "BC";
      LOG.info("use provider {}", providerName);

      for (int i = 0; i < maxSessions; i++) {
        Cipher rsaCipher;
        try {
          final String algo = "RSA/ECB/NoPadding";
          rsaCipher = Cipher.getInstance(algo, providerName);
          LOG.info("use cipher algorithm {}", algo);
        } catch (NoSuchPaddingException ex) {
          throw new NoSuchAlgorithmException("NoSuchPadding", ex);
        } catch (NoSuchAlgorithmException ex) {
          final String algo = "RSA/NONE/NoPadding";
          try {
            rsaCipher = Cipher.getInstance(algo, providerName);
            LOG.info("use cipher algorithm {}", algo);
          } catch (NoSuchPaddingException e1) {
            throw new NoSuchAlgorithmException("NoSuchPadding", ex);
          }
        }
        rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
        rsaCiphers.add(new ConcurrentBagEntry<>(rsaCipher));
      }
    } else {
      String algorithm;
      if (this.publicKey instanceof ECPublicKey) {
        boolean sm2curve = GMUtil.isSm2primev2Curve(
            ((ECPublicKey) this.publicKey).getParams().getCurve());
        algorithm = sm2curve ? null : "NONEwithECDSA";
      } else if (this.publicKey instanceof DSAPublicKey) {
        algorithm = "NONEwithDSA";
      } else {
        throw new IllegalArgumentException("Currently only RSA, DSA and EC public key are "
            + "supported, but not " + this.publicKey.getAlgorithm()
            + " (class: " + this.publicKey.getClass().getName() + ")");
      }

      if (algorithm != null) {
        for (int i = 0; i < maxSessions; i++) {
          Signature dsaSignature = Signature.getInstance(algorithm, "BC");
          dsaSignature.initSign(privateKey, random);
          dsaSignatures.add(new ConcurrentBagEntry<>(dsaSignature));
        }
      } else {
        for (int i = 0; i < maxSessions; i++) {
          SM2Signer sm2signer = new SM2Signer(ECUtil.generatePrivateKeyParameter(privateKey));
          sm2Signers.add(new ConcurrentBagEntry<>(sm2signer));
        }
      }
    }
  } // constructor

  @Override
  protected byte[] digestSecretKey0(long mechanism) throws P11TokenException {
    if (!(signingKey instanceof SecretKey)) {
      throw new P11TokenException("digestSecretKey could not be applied to non-SecretKey");
    }

    HashAlgo hashAlgo = getHashAlgoForPkcs11HashMech(mechanism);
    if (hashAlgo == null) {
      throw new P11TokenException(
          "unknown mechanism " + Functions.mechanismCodeToString(mechanism));
    }
    return hashAlgo.hash(((SecretKey) signingKey).getEncoded());
  }

  @Override
  protected byte[] sign0(long mechanism, P11Params parameters, byte[] content)
      throws P11TokenException {
    if (PKCS11Constants.CKM_ECDSA == mechanism) {
      return dsaAndEcdsaSign(content, null);
    } else if (PKCS11Constants.CKM_ECDSA_SHA1 == mechanism) {
      return dsaAndEcdsaSign(content, HashAlgo.SHA1);
    } else if (PKCS11Constants.CKM_ECDSA_SHA224 == mechanism) {
      return dsaAndEcdsaSign(content, HashAlgo.SHA224);
    } else if (PKCS11Constants.CKM_ECDSA_SHA256 == mechanism) {
      return dsaAndEcdsaSign(content, HashAlgo.SHA256);
    } else if (PKCS11Constants.CKM_ECDSA_SHA384 == mechanism) {
      return dsaAndEcdsaSign(content, HashAlgo.SHA384);
    } else if (PKCS11Constants.CKM_ECDSA_SHA512 == mechanism) {
      return dsaAndEcdsaSign(content, HashAlgo.SHA512);
    } else if (PKCS11Constants.CKM_ECDSA_SHA3_224 == mechanism) {
      return dsaAndEcdsaSign(content, HashAlgo.SHA3_224);
    } else if (PKCS11Constants.CKM_ECDSA_SHA3_256 == mechanism) {
      return dsaAndEcdsaSign(content, HashAlgo.SHA3_256);
    } else if (PKCS11Constants.CKM_ECDSA_SHA3_384 == mechanism) {
      return dsaAndEcdsaSign(content, HashAlgo.SHA3_384);
    } else if (PKCS11Constants.CKM_ECDSA_SHA3_512 == mechanism) {
      return dsaAndEcdsaSign(content, HashAlgo.SHA3_512);
    } else if (PKCS11Constants.CKM_VENDOR_SM2 == mechanism) {
      return sm2SignHash(content);
    } else if (PKCS11Constants.CKM_VENDOR_SM2_SM3 == mechanism) {
      return sm2Sign(parameters, content, HashAlgo.SM3);
    } else if (PKCS11Constants.CKM_DSA == mechanism) {
      return dsaAndEcdsaSign(content, null);
    } else if (PKCS11Constants.CKM_DSA_SHA1 == mechanism) {
      return dsaAndEcdsaSign(content, HashAlgo.SHA1);
    } else if (PKCS11Constants.CKM_DSA_SHA224 == mechanism) {
      return dsaAndEcdsaSign(content, HashAlgo.SHA224);
    } else if (PKCS11Constants.CKM_DSA_SHA256 == mechanism) {
      return dsaAndEcdsaSign(content, HashAlgo.SHA256);
    } else if (PKCS11Constants.CKM_DSA_SHA384 == mechanism) {
      return dsaAndEcdsaSign(content, HashAlgo.SHA384);
    } else if (PKCS11Constants.CKM_DSA_SHA512 == mechanism) {
      return dsaAndEcdsaSign(content, HashAlgo.SHA512);
    } else if (PKCS11Constants.CKM_DSA_SHA3_224 == mechanism) {
      return dsaAndEcdsaSign(content, HashAlgo.SHA3_224);
    } else if (PKCS11Constants.CKM_DSA_SHA3_256 == mechanism) {
      return dsaAndEcdsaSign(content, HashAlgo.SHA3_256);
    } else if (PKCS11Constants.CKM_DSA_SHA3_384 == mechanism) {
      return dsaAndEcdsaSign(content, HashAlgo.SHA3_384);
    } else if (PKCS11Constants.CKM_DSA_SHA3_512 == mechanism) {
      return dsaAndEcdsaSign(content, HashAlgo.SHA3_512);
    } else if (PKCS11Constants.CKM_RSA_X_509 == mechanism) {
      return rsaX509Sign(content);
    } else if (PKCS11Constants.CKM_RSA_PKCS == mechanism) {
      return rsaPkcsSign(content, null);
    } else if (PKCS11Constants.CKM_SHA1_RSA_PKCS == mechanism) {
      return rsaPkcsSign(content, HashAlgo.SHA1);
    } else if (PKCS11Constants.CKM_SHA224_RSA_PKCS == mechanism) {
      return rsaPkcsSign(content, HashAlgo.SHA224);
    } else if (PKCS11Constants.CKM_SHA256_RSA_PKCS == mechanism) {
      return rsaPkcsSign(content, HashAlgo.SHA256);
    } else if (PKCS11Constants.CKM_SHA384_RSA_PKCS == mechanism) {
      return rsaPkcsSign(content, HashAlgo.SHA384);
    } else if (PKCS11Constants.CKM_SHA512_RSA_PKCS == mechanism) {
      return rsaPkcsSign(content, HashAlgo.SHA512);
    } else if (PKCS11Constants.CKM_SHA3_224_RSA_PKCS == mechanism) {
      return rsaPkcsSign(content, HashAlgo.SHA3_224);
    } else if (PKCS11Constants.CKM_SHA3_256_RSA_PKCS == mechanism) {
      return rsaPkcsSign(content, HashAlgo.SHA3_256);
    } else if (PKCS11Constants.CKM_SHA3_384_RSA_PKCS == mechanism) {
      return rsaPkcsSign(content, HashAlgo.SHA3_384);
    } else if (PKCS11Constants.CKM_SHA3_512_RSA_PKCS == mechanism) {
      return rsaPkcsSign(content, HashAlgo.SHA3_512);
    } else if (PKCS11Constants.CKM_RSA_PKCS_PSS == mechanism) {
      return rsaPkcsPssSign(parameters, content, null);
    } else if (PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS == mechanism) {
      return rsaPkcsPssSign(parameters, content, HashAlgo.SHA1);
    } else if (PKCS11Constants.CKM_SHA224_RSA_PKCS_PSS == mechanism) {
      return rsaPkcsPssSign(parameters, content, HashAlgo.SHA224);
    } else if (PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS == mechanism) {
      return rsaPkcsPssSign(parameters, content, HashAlgo.SHA256);
    } else if (PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS == mechanism) {
      return rsaPkcsPssSign(parameters, content, HashAlgo.SHA384);
    } else if (PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS == mechanism) {
      return rsaPkcsPssSign(parameters, content, HashAlgo.SHA512);
    } else if (PKCS11Constants.CKM_SHA3_224_RSA_PKCS_PSS == mechanism) {
      return rsaPkcsPssSign(parameters, content, HashAlgo.SHA3_224);
    } else if (PKCS11Constants.CKM_SHA3_256_RSA_PKCS_PSS == mechanism) {
      return rsaPkcsPssSign(parameters, content, HashAlgo.SHA3_256);
    } else if (PKCS11Constants.CKM_SHA3_384_RSA_PKCS_PSS == mechanism) {
      return rsaPkcsPssSign(parameters, content, HashAlgo.SHA3_384);
    } else if (PKCS11Constants.CKM_SHA3_512_RSA_PKCS_PSS == mechanism) {
      return rsaPkcsPssSign(parameters, content, HashAlgo.SHA3_512);
    } else if (PKCS11Constants.CKM_SHA_1_HMAC == mechanism) {
      return hmac(content, HashAlgo.SHA1);
    } else if (PKCS11Constants.CKM_SHA224_HMAC == mechanism) {
      return hmac(content, HashAlgo.SHA224);
    } else if (PKCS11Constants.CKM_SHA256_HMAC == mechanism) {
      return hmac(content, HashAlgo.SHA256);
    } else if (PKCS11Constants.CKM_SHA384_HMAC == mechanism) {
      return hmac(content, HashAlgo.SHA384);
    } else if (PKCS11Constants.CKM_SHA512_HMAC == mechanism) {
      return hmac(content, HashAlgo.SHA512);
    } else if (PKCS11Constants.CKM_SHA3_224_HMAC == mechanism) {
      return hmac(content, HashAlgo.SHA3_224);
    } else if (PKCS11Constants.CKM_SHA3_256_HMAC == mechanism) {
      return hmac(content, HashAlgo.SHA3_256);
    } else if (PKCS11Constants.CKM_SHA3_384_HMAC == mechanism) {
      return hmac(content, HashAlgo.SHA3_384);
    } else if (PKCS11Constants.CKM_SHA3_512_HMAC == mechanism) {
      return hmac(content, HashAlgo.SHA3_512);
    } else if (PKCS11Constants.CKM_AES_GMAC == mechanism) {
      return aesGmac(parameters, content);
    } else {
      throw new P11TokenException("unsupported mechanism " + mechanism);
    }
  }

  // TODO: check the correctness
  private byte[] hmac(byte[] contentToSign, HashAlgo hashAlgo) {
    HMac hmac = new HMac(hashAlgo.createDigest());
    hmac.init(new KeyParameter(signingKey.getEncoded()));
    hmac.update(contentToSign, 0, contentToSign.length);
    byte[] signature = new byte[hmac.getMacSize()];
    hmac.doFinal(signature, 0);
    return signature;
  }

  // TODO: check the correctness
  private byte[] aesGmac(P11Params params, byte[] contentToSign) throws P11TokenException {
    if (params == null) {
      throw new P11TokenException("iv must not be null");
    }

    byte[] iv;
    if (params instanceof P11IVParams) {
      iv = ((P11IVParams) params).getIV();
    } else {
      throw new P11TokenException("params must be instanceof P11IVParams");
    }

    GMac gmac = new GMac(new GCMBlockCipher(new AESEngine()));
    ParametersWithIV paramsWithIv =
        new ParametersWithIV(new KeyParameter(signingKey.getEncoded()), iv);
    gmac.init(paramsWithIv);
    gmac.update(contentToSign, 0, contentToSign.length);
    byte[] signature = new byte[gmac.getMacSize()];
    gmac.doFinal(signature, 0);
    return signature;
  }

  private byte[] rsaPkcsPssSign(P11Params parameters, byte[] contentToSign,
      HashAlgo hashAlgo) throws P11TokenException {
    if (!(parameters instanceof P11RSAPkcsPssParams)) {
      throw new P11TokenException("the parameters is not of "
          + P11RSAPkcsPssParams.class.getName());
    }

    P11RSAPkcsPssParams pssParam = (P11RSAPkcsPssParams) parameters;
    HashAlgo contentHash = getHashAlgoForPkcs11HashMech(pssParam.getHashAlgorithm());
    if (contentHash == null) {
      throw new P11TokenException("unsupported HashAlgorithm " + pssParam.getHashAlgorithm());
    } else if (hashAlgo != null && contentHash != hashAlgo) {
      throw new P11TokenException("Invalid parameters: invalid hash algorithm");
    }

    HashAlgo mgfHash = getHashAlgoForPkcs11MgfMech(
        pssParam.getMaskGenerationFunction());
    if (mgfHash == null) {
      throw new P11TokenException(
          "unsupported MaskGenerationFunction " + pssParam.getHashAlgorithm());
    }

    byte[] hashValue = (hashAlgo == null) ? contentToSign : hashAlgo.hash(contentToSign);
    byte[] encodedHashValue;
    try {
      encodedHashValue = SignerUtil.EMSA_PSS_ENCODE(contentHash, hashValue, mgfHash,
          (int) pssParam.getSaltLength(), getSignatureKeyBitLength(), random);
    } catch (XiSecurityException ex) {
      throw new P11TokenException("XiSecurityException: " + ex.getMessage(), ex);
    }
    return rsaX509Sign(encodedHashValue);
  }

  private byte[] rsaPkcsSign(byte[] contentToSign, HashAlgo hashAlgo) throws P11TokenException {
    int modulusBitLen = getSignatureKeyBitLength();
    byte[] paddedHash;
    try {
      if (hashAlgo == null) {
        paddedHash = SignerUtil.EMSA_PKCS1_v1_5_encoding(contentToSign, modulusBitLen);
      } else {
        byte[] hash = hashAlgo.hash(contentToSign);
        paddedHash = SignerUtil.EMSA_PKCS1_v1_5_encoding(hash, modulusBitLen, hashAlgo);
      }
    } catch (XiSecurityException ex) {
      throw new P11TokenException("XiSecurityException: " + ex.getMessage(), ex);
    }

    return rsaX509Sign(paddedHash);
  }

  private byte[] rsaX509Sign(byte[] dataToSign) throws P11TokenException {
    ConcurrentBagEntry<Cipher> cipher;
    try {
      cipher = rsaCiphers.borrow(5000, TimeUnit.MILLISECONDS);
    } catch (InterruptedException ex) {
      throw new P11TokenException("could not take any idle signer");
    }

    if (cipher == null) {
      throw new P11TokenException("no idle RSA cipher available");
    }

    try {
      return cipher.value().doFinal(dataToSign);
    } catch (BadPaddingException ex) {
      throw new P11TokenException("BadPaddingException: " + ex.getMessage(), ex);
    } catch (IllegalBlockSizeException ex) {
      throw new P11TokenException("IllegalBlockSizeException: " + ex.getMessage(), ex);
    } finally {
      rsaCiphers.requite(cipher);
    }
  }

  private byte[] dsaAndEcdsaSign(byte[] dataToSign, HashAlgo hashAlgo)
      throws P11TokenException {
    byte[] hash = (hashAlgo == null) ? dataToSign : hashAlgo.hash(dataToSign);

    ConcurrentBagEntry<Signature> sig0;
    try {
      sig0 = dsaSignatures.borrow(5000, TimeUnit.MILLISECONDS);
    } catch (InterruptedException ex) {
      throw new P11TokenException("InterruptedException occurs while retrieving idle signature");
    }

    if (sig0 == null) {
      throw new P11TokenException("no idle DSA Signature available");
    }

    try {
      Signature sig = sig0.value();
      sig.update(hash);
      byte[] x962Signature = sig.sign();
      return SignerUtil.dsaSigX962ToPlain(x962Signature, getSignatureKeyBitLength());
    } catch (SignatureException ex) {
      throw new P11TokenException("SignatureException: " + ex.getMessage(), ex);
    } catch (XiSecurityException ex) {
      throw new P11TokenException("XiSecurityException: " + ex.getMessage(), ex);
    } finally {
      dsaSignatures.requite(sig0);
    }
  }

  private byte[] sm2SignHash(byte[] hash) throws P11TokenException {
    ConcurrentBagEntry<SM2Signer> sig0;
    try {
      sig0 = sm2Signers.borrow(5000, TimeUnit.MILLISECONDS);
    } catch (InterruptedException ex) {
      throw new P11TokenException("InterruptedException occurs while retrieving idle signature");
    }

    if (sig0 == null) {
      throw new P11TokenException("no idle SM2 Signer available");
    }

    try {
      SM2Signer sig = sig0.value();
      byte[] x962Signature = sig.generateSignatureForHash(hash);
      return SignerUtil.dsaSigX962ToPlain(x962Signature, getSignatureKeyBitLength());
    } catch (CryptoException ex) {
      throw new P11TokenException("CryptoException: " + ex.getMessage(), ex);
    } catch (XiSecurityException ex) {
      throw new P11TokenException("XiSecurityException: " + ex.getMessage(), ex);
    } finally {
      sm2Signers.requite(sig0);
    }
  }

  private byte[] sm2Sign(P11Params params, byte[] dataToSign, HashAlgo hash)
      throws P11TokenException {
    if (params == null) {
      throw new P11TokenException("userId must not be null");
    }

    byte[] userId;
    if (params instanceof P11ByteArrayParams) {
      userId = ((P11ByteArrayParams) params).getBytes();
    } else {
      throw new P11TokenException("params must be instanceof P11ByteArrayParams");
    }

    ConcurrentBagEntry<SM2Signer> sig0;
    try {
      sig0 = sm2Signers.borrow(5000, TimeUnit.MILLISECONDS);
    } catch (InterruptedException ex) {
      throw new P11TokenException("InterruptedException occurs while retrieving idle signature");
    }

    if (sig0 == null) {
      throw new P11TokenException("no idle SM2 Signer available");
    }

    try {
      SM2Signer sig = sig0.value();

      byte[] x962Signature = sig.generateSignatureForMessage(userId, dataToSign);
      return SignerUtil.dsaSigX962ToPlain(x962Signature, getSignatureKeyBitLength());
    } catch (CryptoException ex) {
      throw new P11TokenException("CryptoException: " + ex.getMessage(), ex);
    } catch (XiSecurityException ex) {
      throw new P11TokenException("XiSecurityException: " + ex.getMessage(), ex);
    } finally {
      sm2Signers.requite(sig0);
    }
  }

  Key getSigningKey() {
    return signingKey;
  }

  private static HashAlgo getHashAlgoForPkcs11HashMech(long hashMech) {
    if (hashMech == PKCS11Constants.CKM_SHA_1) {
      return HashAlgo.SHA1;
    } else if (hashMech == PKCS11Constants.CKM_SHA224) {
      return HashAlgo.SHA224;
    } else if (hashMech == PKCS11Constants.CKM_SHA256) {
      return HashAlgo.SHA256;
    } else if (hashMech == PKCS11Constants.CKM_SHA384) {
      return HashAlgo.SHA384;
    } else if (hashMech == PKCS11Constants.CKM_SHA512) {
      return HashAlgo.SHA512;
    } else if (hashMech == PKCS11Constants.CKM_SHA3_224) {
      return HashAlgo.SHA3_224;
    } else if (hashMech == PKCS11Constants.CKM_SHA3_256) {
      return HashAlgo.SHA3_256;
    } else if (hashMech == PKCS11Constants.CKM_SHA3_384) {
      return HashAlgo.SHA3_384;
    } else if (hashMech == PKCS11Constants.CKM_SHA3_512) {
      return HashAlgo.SHA3_512;
    } else if (hashMech == PKCS11Constants.CKM_VENDOR_SM3) {
      return HashAlgo.SM3;
    } else {
      return null;
    }
  }

  private static HashAlgo getHashAlgoForPkcs11MgfMech(long hashMech) {
    if (hashMech == PKCS11Constants.CKG_MGF1_SHA1) {
      return HashAlgo.SHA1;
    } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA224) {
      return HashAlgo.SHA224;
    } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA256) {
      return HashAlgo.SHA256;
    } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA384) {
      return HashAlgo.SHA384;
    } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA512) {
      return HashAlgo.SHA512;
    } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA3_224) {
      return HashAlgo.SHA3_224;
    } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA3_256) {
      return HashAlgo.SHA3_256;
    } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA3_384) {
      return HashAlgo.SHA3_384;
    } else if (hashMech == PKCS11Constants.CKG_MGF1_SHA3_512) {
      return HashAlgo.SHA3_512;
    } else {
      // SM3 does not apply to RSAPSS signature
      return null;
    }
  }

}
