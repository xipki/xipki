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

package org.xipki.security.pkcs11.emulator;

import static org.xipki.util.Args.notNull;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
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
import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.P11Identity;
import org.xipki.security.pkcs11.P11IdentityId;
import org.xipki.security.pkcs11.P11Params;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11TokenException;
import org.xipki.security.util.GMUtil;
import org.xipki.security.util.SignerUtil;
import org.xipki.util.concurrent.ConcurrentBag;
import org.xipki.util.concurrent.ConcurrentBagEntry;

import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * {@link P11Identity} for PKCS#11 emulator.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class EmulatorP11Identity extends P11Identity {

  private static final Logger LOG = LoggerFactory.getLogger(EmulatorP11Identity.class);

  private static final Map<Long, HashAlgo> mgfMechHashMap = new HashMap<>();

  private static final Map<Long, HashAlgo> mechHashMap = new HashMap<>();

  private final Key signingKey;

  private final ConcurrentBag<ConcurrentBagEntry<Cipher>> rsaCiphers = new ConcurrentBag<>();

  private final ConcurrentBag<ConcurrentBagEntry<Signature>> dsaSignatures =
      new ConcurrentBag<>();

  private final ConcurrentBag<ConcurrentBagEntry<Signature>> eddsaSignatures =
      new ConcurrentBag<>();

  private final ConcurrentBag<ConcurrentBagEntry<SM2Signer>> sm2Signers = new ConcurrentBag<>();

  private final SecureRandom random;

  static {
    // MGF1 mechanisms
    mgfMechHashMap.put(PKCS11Constants.CKG_MGF1_SHA1,     HashAlgo.SHA1);
    mgfMechHashMap.put(PKCS11Constants.CKG_MGF1_SHA224,   HashAlgo.SHA224);
    mgfMechHashMap.put(PKCS11Constants.CKG_MGF1_SHA256,   HashAlgo.SHA256);
    mgfMechHashMap.put(PKCS11Constants.CKG_MGF1_SHA384,   HashAlgo.SHA384);
    mgfMechHashMap.put(PKCS11Constants.CKG_MGF1_SHA512,   HashAlgo.SHA512);
    mgfMechHashMap.put(PKCS11Constants.CKG_MGF1_SHA3_224, HashAlgo.SHA3_224);
    mgfMechHashMap.put(PKCS11Constants.CKG_MGF1_SHA3_256, HashAlgo.SHA3_256);
    mgfMechHashMap.put(PKCS11Constants.CKG_MGF1_SHA3_384, HashAlgo.SHA3_384);
    mgfMechHashMap.put(PKCS11Constants.CKG_MGF1_SHA3_512, HashAlgo.SHA3_512);

    // Hash mechanisms
    mechHashMap.put(PKCS11Constants.CKM_SHA_1,      HashAlgo.SHA1);
    mechHashMap.put(PKCS11Constants.CKM_SHA224,     HashAlgo.SHA224);
    mechHashMap.put(PKCS11Constants.CKM_SHA256,     HashAlgo.SHA256);
    mechHashMap.put(PKCS11Constants.CKM_SHA384,     HashAlgo.SHA384);
    mechHashMap.put(PKCS11Constants.CKM_SHA512,     HashAlgo.SHA512);
    mechHashMap.put(PKCS11Constants.CKM_SHA3_224,   HashAlgo.SHA3_224);
    mechHashMap.put(PKCS11Constants.CKM_SHA3_256,   HashAlgo.SHA3_256);
    mechHashMap.put(PKCS11Constants.CKM_SHA3_384,   HashAlgo.SHA3_384);
    mechHashMap.put(PKCS11Constants.CKM_SHA3_512,   HashAlgo.SHA3_512);
    mechHashMap.put(PKCS11Constants.CKM_VENDOR_SM3, HashAlgo.SM3);

    // ECDSA sign mechanisms
    mechHashMap.put(PKCS11Constants.CKM_ECDSA_SHA1,     HashAlgo.SHA1);
    mechHashMap.put(PKCS11Constants.CKM_ECDSA_SHA224,   HashAlgo.SHA224);
    mechHashMap.put(PKCS11Constants.CKM_ECDSA_SHA256,   HashAlgo.SHA256);
    mechHashMap.put(PKCS11Constants.CKM_ECDSA_SHA384,   HashAlgo.SHA384);
    mechHashMap.put(PKCS11Constants.CKM_ECDSA_SHA512,   HashAlgo.SHA512);
    mechHashMap.put(PKCS11Constants.CKM_ECDSA_SHA3_224, HashAlgo.SHA3_224);
    mechHashMap.put(PKCS11Constants.CKM_ECDSA_SHA3_256, HashAlgo.SHA3_256);
    mechHashMap.put(PKCS11Constants.CKM_ECDSA_SHA3_384, HashAlgo.SHA3_384);
    mechHashMap.put(PKCS11Constants.CKM_ECDSA_SHA3_512, HashAlgo.SHA3_512);

    // SM2 sign mechanisms
    mechHashMap.put(PKCS11Constants.CKM_VENDOR_SM2_SM3, HashAlgo.SM3);

    // DSA sign mechanisms
    mechHashMap.put(PKCS11Constants.CKM_DSA_SHA1,     HashAlgo.SHA1);
    mechHashMap.put(PKCS11Constants.CKM_DSA_SHA224,   HashAlgo.SHA224);
    mechHashMap.put(PKCS11Constants.CKM_DSA_SHA256,   HashAlgo.SHA256);
    mechHashMap.put(PKCS11Constants.CKM_DSA_SHA384,   HashAlgo.SHA384);
    mechHashMap.put(PKCS11Constants.CKM_DSA_SHA512,   HashAlgo.SHA512);
    mechHashMap.put(PKCS11Constants.CKM_DSA_SHA3_224, HashAlgo.SHA3_224);
    mechHashMap.put(PKCS11Constants.CKM_DSA_SHA3_256, HashAlgo.SHA3_256);
    mechHashMap.put(PKCS11Constants.CKM_DSA_SHA3_384, HashAlgo.SHA3_384);
    mechHashMap.put(PKCS11Constants.CKM_DSA_SHA3_512, HashAlgo.SHA3_512);

    // RSA PKCS#1v1.5 sign mechanisms
    mechHashMap.put(PKCS11Constants.CKM_SHA1_RSA_PKCS,       HashAlgo.SHA1);
    mechHashMap.put(PKCS11Constants.CKM_SHA224_RSA_PKCS,     HashAlgo.SHA224);
    mechHashMap.put(PKCS11Constants.CKM_SHA256_RSA_PKCS,     HashAlgo.SHA256);
    mechHashMap.put(PKCS11Constants.CKM_SHA384_RSA_PKCS,     HashAlgo.SHA384);
    mechHashMap.put(PKCS11Constants.CKM_SHA512_RSA_PKCS,     HashAlgo.SHA512);
    mechHashMap.put(PKCS11Constants.CKM_SHA3_224_RSA_PKCS,   HashAlgo.SHA3_224);
    mechHashMap.put(PKCS11Constants.CKM_SHA3_256_RSA_PKCS,   HashAlgo.SHA3_256);
    mechHashMap.put(PKCS11Constants.CKM_SHA3_384_RSA_PKCS,   HashAlgo.SHA3_384);
    mechHashMap.put(PKCS11Constants.CKM_SHA3_512_RSA_PKCS,   HashAlgo.SHA3_512);

    // RSA PSS MGF1 sign mechanisms
    mechHashMap.put(PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS,     HashAlgo.SHA1);
    mechHashMap.put(PKCS11Constants.CKM_SHA224_RSA_PKCS_PSS,   HashAlgo.SHA224);
    mechHashMap.put(PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS,   HashAlgo.SHA256);
    mechHashMap.put(PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS,   HashAlgo.SHA384);
    mechHashMap.put(PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS,   HashAlgo.SHA512);
    mechHashMap.put(PKCS11Constants.CKM_SHA3_224_RSA_PKCS_PSS, HashAlgo.SHA3_224);
    mechHashMap.put(PKCS11Constants.CKM_SHA3_256_RSA_PKCS_PSS, HashAlgo.SHA3_256);
    mechHashMap.put(PKCS11Constants.CKM_SHA3_384_RSA_PKCS_PSS, HashAlgo.SHA3_384);
    mechHashMap.put(PKCS11Constants.CKM_SHA3_512_RSA_PKCS_PSS, HashAlgo.SHA3_512);

    // HMAC
    mechHashMap.put(PKCS11Constants.CKM_SHA_1_HMAC,    HashAlgo.SHA1);
    mechHashMap.put(PKCS11Constants.CKM_SHA224_HMAC,   HashAlgo.SHA224);
    mechHashMap.put(PKCS11Constants.CKM_SHA256_HMAC,   HashAlgo.SHA256);
    mechHashMap.put(PKCS11Constants.CKM_SHA384_HMAC,   HashAlgo.SHA384);
    mechHashMap.put(PKCS11Constants.CKM_SHA512_HMAC,   HashAlgo.SHA512);
    mechHashMap.put(PKCS11Constants.CKM_SHA3_224_HMAC, HashAlgo.SHA224);
    mechHashMap.put(PKCS11Constants.CKM_SHA3_256_HMAC, HashAlgo.SHA256);
    mechHashMap.put(PKCS11Constants.CKM_SHA3_384_HMAC, HashAlgo.SHA384);
    mechHashMap.put(PKCS11Constants.CKM_SHA3_512_HMAC, HashAlgo.SHA512);
  }

  public EmulatorP11Identity(P11Slot slot, P11IdentityId identityId,
      SecretKey signingKey, int maxSessions, SecureRandom random) {
    super(slot, identityId, 0);
    this.signingKey = notNull(signingKey, "signingKey");
    this.random = notNull(random, "random");
  } // constructor

  public EmulatorP11Identity(P11Slot slot, P11IdentityId identityId, PrivateKey privateKey,
      PublicKey publicKey, X509Cert[] certificateChain, int maxSessions,
      SecureRandom random)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
    super(slot, identityId, publicKey, certificateChain);
    this.signingKey = notNull(privateKey, "privateKey");
    this.random = notNull(random, "random");

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
      } else if (this.publicKey instanceof EdDSAKey) {
        algorithm = null;
      } else if (this.publicKey instanceof XDHKey) {
        algorithm = null;
      } else {
        throw new IllegalArgumentException("Currently only RSA, DSA, EC, EC Edwards and EC "
            + "Montgomery public key are supported, but not " + this.publicKey.getAlgorithm()
            + " (class: " + this.publicKey.getClass().getName() + ")");
      }

      if (algorithm != null) {
        for (int i = 0; i < maxSessions; i++) {
          Signature dsaSignature = Signature.getInstance(algorithm, "BC");
          dsaSignature.initSign(privateKey, random);
          dsaSignatures.add(new ConcurrentBagEntry<>(dsaSignature));
        }
      } else if (this.publicKey instanceof EdDSAKey) {
        algorithm = this.publicKey.getAlgorithm();
        for (int i = 0; i < maxSessions; i++) {
          Signature signature = Signature.getInstance(algorithm, "BC");
          signature.initSign(privateKey);
          eddsaSignatures.add(new ConcurrentBagEntry<>(signature));
        }
      } else if (this.publicKey instanceof XDHKey) {
        // do nothing. not suitable for sign.
      } else {
        for (int i = 0; i < maxSessions; i++) {
          SM2Signer sm2signer = new SM2Signer(ECUtil.generatePrivateKeyParameter(privateKey));
          sm2Signers.add(new ConcurrentBagEntry<>(sm2signer));
        }
      }
    }
  } // constructor

  @Override
  protected byte[] digestSecretKey0(long mechanism)
      throws P11TokenException {
    if (!(signingKey instanceof SecretKey)) {
      throw new P11TokenException("digestSecretKey could not be applied to non-SecretKey");
    }

    HashAlgo hashAlgo =  mechHashMap.get(mechanism);
    if (hashAlgo == null) {
      throw new P11TokenException(
          "unknown mechanism " + Functions.mechanismCodeToString(mechanism));
    }
    return hashAlgo.hash(signingKey.getEncoded());
  }

  @Override
  protected byte[] sign0(long mechanism, P11Params parameters, byte[] content)
      throws P11TokenException {
    if (mechanism == PKCS11Constants.CKM_ECDSA) {
      return dsaAndEcdsaSign(content, null);
    } else if (mechanism == PKCS11Constants.CKM_VENDOR_SM2) {
      return sm2SignHash(content);
    } else if (mechanism == PKCS11Constants.CKM_DSA) {
      return dsaAndEcdsaSign(content, null);
    } else if (mechanism == PKCS11Constants.CKM_EDDSA) {
      return eddsaSign(content);
    } else if (mechanism == PKCS11Constants.CKM_RSA_X_509) {
      return rsaX509Sign(content);
    } else if (mechanism == PKCS11Constants.CKM_RSA_PKCS) {
      return rsaPkcsSign(content, null);
    } else if (PKCS11Constants.CKM_RSA_PKCS_PSS == mechanism) {
      return rsaPkcsPssSign(parameters, content, null);
    } else if (PKCS11Constants.CKM_AES_GMAC == mechanism) {
      return aesGmac(parameters, content);
    }

    HashAlgo hashAlgo = mechHashMap.get(mechanism);
    if (mechanism == PKCS11Constants.CKM_ECDSA_SHA1
        || mechanism == PKCS11Constants.CKM_ECDSA_SHA224
        || mechanism == PKCS11Constants.CKM_ECDSA_SHA256
        || mechanism == PKCS11Constants.CKM_ECDSA_SHA384
        || mechanism == PKCS11Constants.CKM_ECDSA_SHA512
        || mechanism == PKCS11Constants.CKM_ECDSA_SHA3_224
        || mechanism == PKCS11Constants.CKM_ECDSA_SHA3_256
        || mechanism == PKCS11Constants.CKM_ECDSA_SHA3_384
        || mechanism == PKCS11Constants.CKM_ECDSA_SHA3_512) {
      return dsaAndEcdsaSign(content, hashAlgo);
    } else if (mechanism == PKCS11Constants.CKM_VENDOR_SM2_SM3) {
      return sm2Sign(parameters, content, hashAlgo);
    } else if (mechanism == PKCS11Constants.CKM_DSA_SHA1
        || mechanism == PKCS11Constants.CKM_DSA_SHA224
        || mechanism == PKCS11Constants.CKM_DSA_SHA256
        || mechanism == PKCS11Constants.CKM_DSA_SHA384
        || mechanism == PKCS11Constants.CKM_DSA_SHA512
        || mechanism == PKCS11Constants.CKM_DSA_SHA3_224
        || mechanism == PKCS11Constants.CKM_DSA_SHA3_256
        || mechanism == PKCS11Constants.CKM_DSA_SHA3_384
        || mechanism == PKCS11Constants.CKM_DSA_SHA3_512) {
      return dsaAndEcdsaSign(content, hashAlgo);
    } else if (mechanism == PKCS11Constants.CKM_SHA1_RSA_PKCS
        || mechanism == PKCS11Constants.CKM_SHA224_RSA_PKCS
        || mechanism == PKCS11Constants.CKM_SHA256_RSA_PKCS
        || mechanism == PKCS11Constants.CKM_SHA384_RSA_PKCS
        || mechanism == PKCS11Constants.CKM_SHA512_RSA_PKCS
        || mechanism == PKCS11Constants.CKM_SHA3_224_RSA_PKCS
        || mechanism == PKCS11Constants.CKM_SHA3_256_RSA_PKCS
        || mechanism == PKCS11Constants.CKM_SHA3_384_RSA_PKCS
        || mechanism == PKCS11Constants.CKM_SHA3_512_RSA_PKCS) {
      return rsaPkcsSign(content, hashAlgo);
    } else if (mechanism == PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS
        || mechanism == PKCS11Constants.CKM_SHA224_RSA_PKCS_PSS
        || mechanism == PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS
        || mechanism == PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS
        || mechanism == PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS
        || mechanism == PKCS11Constants.CKM_SHA3_224_RSA_PKCS_PSS
        || mechanism == PKCS11Constants.CKM_SHA3_256_RSA_PKCS_PSS
        || mechanism == PKCS11Constants.CKM_SHA3_384_RSA_PKCS_PSS
        || mechanism == PKCS11Constants.CKM_SHA3_512_RSA_PKCS_PSS) {
      return rsaPkcsPssSign(parameters, content, hashAlgo);
    } else if (mechanism == PKCS11Constants.CKM_SHA_1_HMAC
        || mechanism == PKCS11Constants.CKM_SHA224_HMAC
        || mechanism == PKCS11Constants.CKM_SHA256_HMAC
        || mechanism == PKCS11Constants.CKM_SHA384_HMAC
        || mechanism == PKCS11Constants.CKM_SHA512_HMAC
        || mechanism == PKCS11Constants.CKM_SHA3_224_HMAC
        || mechanism == PKCS11Constants.CKM_SHA3_256_HMAC
        || mechanism == PKCS11Constants.CKM_SHA3_384_HMAC
        || mechanism == PKCS11Constants.CKM_SHA3_512_HMAC) {
      return hmac(content, hashAlgo);
    } else {
      throw new P11TokenException("unsupported mechanism " + mechanism);
    }
  } // method sign0

  private byte[] hmac(byte[] contentToSign, HashAlgo hashAlgo) {
    HMac hmac = new HMac(hashAlgo.createDigest());
    hmac.init(new KeyParameter(signingKey.getEncoded()));
    hmac.update(contentToSign, 0, contentToSign.length);
    byte[] signature = new byte[hmac.getMacSize()];
    hmac.doFinal(signature, 0);
    return signature;
  } // method hmac

  private byte[] aesGmac(P11Params params, byte[] contentToSign)
      throws P11TokenException {
    if (params == null) {
      throw new P11TokenException("iv may not be null");
    }

    byte[] iv;
    if (params instanceof P11Params.P11IVParams) {
      iv = ((P11Params.P11IVParams) params).getIV();
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
  } // method aesGmac

  private byte[] rsaPkcsPssSign(P11Params parameters, byte[] contentToSign, HashAlgo hashAlgo)
      throws P11TokenException {
    if (!(parameters instanceof P11Params.P11RSAPkcsPssParams)) {
      throw new P11TokenException("the parameters is not of "
          + P11Params.P11RSAPkcsPssParams.class.getName());
    }

    P11Params.P11RSAPkcsPssParams pssParam = (P11Params.P11RSAPkcsPssParams) parameters;
    HashAlgo contentHash =  mechHashMap.get(pssParam.getHashAlgorithm());
    if (contentHash == null) {
      throw new P11TokenException("unsupported HashAlgorithm " + pssParam.getHashAlgorithm());
    } else if (hashAlgo != null && contentHash != hashAlgo) {
      throw new P11TokenException("Invalid parameters: invalid hash algorithm");
    }

    HashAlgo mgfHash =  mgfMechHashMap.get(pssParam.getMaskGenerationFunction());
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
  } // method rsaPkcsPssSign

  private byte[] rsaPkcsSign(byte[] contentToSign, HashAlgo hashAlgo)
      throws P11TokenException {
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
  } // method rsaPkcsSign

  private byte[] rsaX509Sign(byte[] dataToSign)
      throws P11TokenException {
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
  } // method rsaX509Sign

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
  } // method dsaAndEcdsaSign

  private byte[] eddsaSign(byte[] dataToSign)
      throws P11TokenException {
    if (!(signingKey instanceof EdDSAKey)) {
      throw new P11TokenException("given signing key is not suitable for EdDSA sign");
    }

    ConcurrentBagEntry<Signature> sig0;
    try {
      sig0 = eddsaSignatures.borrow(5000, TimeUnit.MILLISECONDS);
    } catch (InterruptedException ex) {
      throw new P11TokenException("InterruptedException occurs while retrieving idle signature");
    }

    if (sig0 == null) {
      throw new P11TokenException("no idle DSA Signature available");
    }

    try {
      Signature sig = sig0.value();
      sig.update(dataToSign);
      return sig.sign();
    } catch (SignatureException ex) {
      throw new P11TokenException("SignatureException: " + ex.getMessage(), ex);
    } finally {
      eddsaSignatures.requite(sig0);
    }
  } // method eddsaSign

  private byte[] sm2SignHash(byte[] hash)
      throws P11TokenException {
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
  } // method sm2SignHash

  private byte[] sm2Sign(P11Params params, byte[] dataToSign, HashAlgo hash)
      throws P11TokenException {
    if (params == null) {
      throw new P11TokenException("userId may not be null");
    }

    byte[] userId;
    if (params instanceof P11Params.P11ByteArrayParams) {
      userId = ((P11Params.P11ByteArrayParams) params).getBytes();
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
  } // method sm2Sign

  Key getSigningKey() {
    return signingKey;
  }

}
