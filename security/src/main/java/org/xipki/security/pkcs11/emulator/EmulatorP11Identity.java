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

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.EdECConstants;
import org.xipki.security.HashAlgo;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.*;
import org.xipki.security.util.PKCS1Util;
import org.xipki.security.util.SignerUtil;
import org.xipki.util.concurrent.ConcurrentBag;
import org.xipki.util.concurrent.ConcurrentBagEntry;

import javax.crypto.*;
import java.security.*;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.xipki.pkcs11.PKCS11Constants.*;
import static org.xipki.security.HashAlgo.*;
import static org.xipki.util.Args.notNull;

/**
 * {@link P11Identity} for PKCS#11 emulator.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class EmulatorP11Identity extends P11Identity {

  private static final Logger LOG = LoggerFactory.getLogger(EmulatorP11Identity.class);

  private static final Map<Long, HashAlgo> mgfMechHashMap = new HashMap<>();

  private static final Map<Long, HashAlgo> mechHashMap = new HashMap<>();

  private final Key signingKey;

  private final ConcurrentBag<ConcurrentBagEntry<Cipher>> rsaCiphers = new ConcurrentBag<>();

  private final ConcurrentBag<ConcurrentBagEntry<Signature>> dsaSignatures = new ConcurrentBag<>();

  private final ConcurrentBag<ConcurrentBagEntry<Signature>> eddsaSignatures = new ConcurrentBag<>();

  private final ConcurrentBag<ConcurrentBagEntry<EmulatorSM2Signer>> sm2Signers = new ConcurrentBag<>();

  private final SecureRandom random;

  private final int maxSessions;

  private boolean initialized;

  static {
    // MGF1 mechanisms
    mgfMechHashMap.put(CKG_MGF1_SHA1,     SHA1);
    mgfMechHashMap.put(CKG_MGF1_SHA224,   SHA224);
    mgfMechHashMap.put(CKG_MGF1_SHA256,   SHA256);
    mgfMechHashMap.put(CKG_MGF1_SHA384,   SHA384);
    mgfMechHashMap.put(CKG_MGF1_SHA512,   SHA512);
    mgfMechHashMap.put(CKG_MGF1_SHA3_224, SHA3_224);
    mgfMechHashMap.put(CKG_MGF1_SHA3_256, SHA3_256);
    mgfMechHashMap.put(CKG_MGF1_SHA3_384, SHA3_384);
    mgfMechHashMap.put(CKG_MGF1_SHA3_512, SHA3_512);

    // Hash mechanisms
    mechHashMap.put(CKM_SHA_1,      SHA1);
    mechHashMap.put(CKM_SHA224,     SHA224);
    mechHashMap.put(CKM_SHA256,     SHA256);
    mechHashMap.put(CKM_SHA384,     SHA384);
    mechHashMap.put(CKM_SHA512,     SHA512);
    mechHashMap.put(CKM_SHA3_224,   SHA3_224);
    mechHashMap.put(CKM_SHA3_256,   SHA3_256);
    mechHashMap.put(CKM_SHA3_384,   SHA3_384);
    mechHashMap.put(CKM_SHA3_512,   SHA3_512);
    mechHashMap.put(CKM_VENDOR_SM3, SM3);

    // ECDSA sign mechanisms
    mechHashMap.put(CKM_ECDSA_SHA1,     SHA1);
    mechHashMap.put(CKM_ECDSA_SHA224,   SHA224);
    mechHashMap.put(CKM_ECDSA_SHA256,   SHA256);
    mechHashMap.put(CKM_ECDSA_SHA384,   SHA384);
    mechHashMap.put(CKM_ECDSA_SHA512,   SHA512);
    mechHashMap.put(CKM_ECDSA_SHA3_224, SHA3_224);
    mechHashMap.put(CKM_ECDSA_SHA3_256, SHA3_256);
    mechHashMap.put(CKM_ECDSA_SHA3_384, SHA3_384);
    mechHashMap.put(CKM_ECDSA_SHA3_512, SHA3_512);

    // SM2 sign mechanisms
    mechHashMap.put(CKM_VENDOR_SM2_SM3, SM3);

    // DSA sign mechanisms
    mechHashMap.put(CKM_DSA_SHA1,     SHA1);
    mechHashMap.put(CKM_DSA_SHA224,   SHA224);
    mechHashMap.put(CKM_DSA_SHA256,   SHA256);
    mechHashMap.put(CKM_DSA_SHA384,   SHA384);
    mechHashMap.put(CKM_DSA_SHA512,   SHA512);
    mechHashMap.put(CKM_DSA_SHA3_224, SHA3_224);
    mechHashMap.put(CKM_DSA_SHA3_256, SHA3_256);
    mechHashMap.put(CKM_DSA_SHA3_384, SHA3_384);
    mechHashMap.put(CKM_DSA_SHA3_512, SHA3_512);

    // RSA PKCS#1v1.5 sign mechanisms
    mechHashMap.put(CKM_SHA1_RSA_PKCS,       SHA1);
    mechHashMap.put(CKM_SHA224_RSA_PKCS,     SHA224);
    mechHashMap.put(CKM_SHA256_RSA_PKCS,     SHA256);
    mechHashMap.put(CKM_SHA384_RSA_PKCS,     SHA384);
    mechHashMap.put(CKM_SHA512_RSA_PKCS,     SHA512);
    mechHashMap.put(CKM_SHA3_224_RSA_PKCS,   SHA3_224);
    mechHashMap.put(CKM_SHA3_256_RSA_PKCS,   SHA3_256);
    mechHashMap.put(CKM_SHA3_384_RSA_PKCS,   SHA3_384);
    mechHashMap.put(CKM_SHA3_512_RSA_PKCS,   SHA3_512);

    // RSA PSS MGF1 sign mechanisms
    mechHashMap.put(CKM_SHA1_RSA_PKCS_PSS,     SHA1);
    mechHashMap.put(CKM_SHA224_RSA_PKCS_PSS,   SHA224);
    mechHashMap.put(CKM_SHA256_RSA_PKCS_PSS,   SHA256);
    mechHashMap.put(CKM_SHA384_RSA_PKCS_PSS,   SHA384);
    mechHashMap.put(CKM_SHA512_RSA_PKCS_PSS,   SHA512);
    mechHashMap.put(CKM_SHA3_224_RSA_PKCS_PSS, SHA3_224);
    mechHashMap.put(CKM_SHA3_256_RSA_PKCS_PSS, SHA3_256);
    mechHashMap.put(CKM_SHA3_384_RSA_PKCS_PSS, SHA3_384);
    mechHashMap.put(CKM_SHA3_512_RSA_PKCS_PSS, SHA3_512);

    // HMAC
    mechHashMap.put(CKM_SHA_1_HMAC,    SHA1);
    mechHashMap.put(CKM_SHA224_HMAC,   SHA224);
    mechHashMap.put(CKM_SHA256_HMAC,   SHA256);
    mechHashMap.put(CKM_SHA384_HMAC,   SHA384);
    mechHashMap.put(CKM_SHA512_HMAC,   SHA512);
    mechHashMap.put(CKM_SHA3_224_HMAC, SHA224);
    mechHashMap.put(CKM_SHA3_256_HMAC, SHA256);
    mechHashMap.put(CKM_SHA3_384_HMAC, SHA384);
    mechHashMap.put(CKM_SHA3_512_HMAC, SHA512);
  }

  public EmulatorP11Identity(
      P11Slot slot, P11IdentityId identityId, Key signingKey, int maxSessions, SecureRandom random) {
    super(slot, identityId);
    this.signingKey = notNull(signingKey, "signingKey");
    this.random = notNull(random, "random");
    this.maxSessions = maxSessions;
  } // constructor

  private synchronized void init() throws P11TokenException {
    if (initialized) {
      return;
    }

    long keyType = getKeyType();
    try {
      if (keyType == CKK_RSA) {
        String providerName = "BC";
        LOG.info("use provider {}", providerName);

        for (int i = 0; i < maxSessions; i++) {
          Cipher rsaCipher;
          try {
            final String algo = "RSA/ECB/NoPadding";
            rsaCipher = Cipher.getInstance(algo, providerName);
            LOG.info("use cipher algorithm {}", algo);
          } catch (NoSuchPaddingException ex) {
            throw new P11TokenException("NoSuchPadding", ex);
          } catch (NoSuchAlgorithmException ex) {
            final String algo = "RSA/NONE/NoPadding";
            try {
              rsaCipher = Cipher.getInstance(algo, providerName);
              LOG.info("use cipher algorithm {}", algo);
            } catch (NoSuchPaddingException e1) {
              throw new P11TokenException("NoSuchPadding", ex);
            }
          }
          rsaCipher.init(Cipher.ENCRYPT_MODE, signingKey);
          rsaCiphers.add(new ConcurrentBagEntry<>(rsaCipher));
        }
      } else {
        String algorithm;
        if (keyType == CKK_EC || keyType == CKK_VENDOR_SM2) {
          boolean sm2curve = GMObjectIdentifiers.sm2p256v1.equals(getEcParams());
          algorithm = sm2curve ? null : "NONEwithECDSA";
        } else if (keyType == CKK_DSA) {
          algorithm = "NONEwithDSA";
        } else if (keyType == CKK_EC_EDWARDS) {
          algorithm = null;
        } else if (keyType == CKK_EC_MONTGOMERY) {
          algorithm = null;
        } else {
          throw new P11TokenException("Currently only RSA, DSA, EC, EC Edwards and EC "
                  + "Montgomery public key are supported, but not " + ckkCodeToName(keyType));
        }

        if (algorithm != null) {
          for (int i = 0; i < maxSessions; i++) {
            Signature dsaSignature = Signature.getInstance(algorithm, "BC");
            dsaSignature.initSign((PrivateKey) signingKey, random);
            dsaSignatures.add(new ConcurrentBagEntry<>(dsaSignature));
          }
        } else if (keyType == CKK_EC_EDWARDS) {
          algorithm = EdECConstants.getName(getEcParams());
          for (int i = 0; i < maxSessions; i++) {
            Signature signature = Signature.getInstance(algorithm, "BC");
            signature.initSign((PrivateKey) signingKey);
            eddsaSignatures.add(new ConcurrentBagEntry<>(signature));
          }
        } else if (keyType == CKK_EC_MONTGOMERY) {
          // do nothing. not suitable for sign.
        } else {
          for (int i = 0; i < maxSessions; i++) {
            EmulatorSM2Signer sm2signer =
                new EmulatorSM2Signer(ECUtil.generatePrivateKeyParameter((PrivateKey) signingKey));
            sm2Signers.add(new ConcurrentBagEntry<>(sm2signer));
          }
        }
      }
    } catch (GeneralSecurityException ex) {
      throw new P11TokenException(ex);
    } finally {
      initialized = true;
    }
  }

  @Override
  protected byte[] digestSecretKey0(long mechanism) throws P11TokenException {
    if (!(signingKey instanceof SecretKey)) {
      throw new P11TokenException("digestSecretKey could not be applied to non-SecretKey");
    }

    HashAlgo hashAlgo =  mechHashMap.get(mechanism);
    if (hashAlgo == null) {
      throw new P11TokenException("unknown mechanism " + ckmCodeToName(mechanism));
    }
    return hashAlgo.hash(signingKey.getEncoded());
  }

  @Override
  public void destroy() throws P11TokenException {
    slot.destroyObjectsForId(id.getKeyId().getId());
  }

  @Override
  protected byte[] sign0(long mechanism, P11Params parameters, byte[] content)
      throws P11TokenException {
    init();

    if (mechanism == CKM_ECDSA) {
      return dsaAndEcdsaSign(content, null);
    } else if (mechanism == CKM_VENDOR_SM2) {
      return sm2SignHash(content);
    } else if (mechanism == CKM_DSA) {
      return dsaAndEcdsaSign(content, null);
    } else if (mechanism == CKM_EDDSA) {
      return eddsaSign(content);
    } else if (mechanism == CKM_RSA_X_509) {
      return rsaX509Sign(content);
    } else if (mechanism == CKM_RSA_PKCS) {
      return rsaPkcsSign(content, null);
    } else if (CKM_RSA_PKCS_PSS == mechanism) {
      return rsaPkcsPssSign(parameters, content, null);
    } else if (CKM_AES_GMAC == mechanism) {
      return aesGmac(parameters, content);
    }

    HashAlgo hashAlgo = mechHashMap.get(mechanism);
    if (   mechanism == CKM_ECDSA_SHA1     || mechanism == CKM_ECDSA_SHA224   || mechanism == CKM_ECDSA_SHA256
        || mechanism == CKM_ECDSA_SHA384   || mechanism == CKM_ECDSA_SHA512   || mechanism == CKM_ECDSA_SHA3_224
        || mechanism == CKM_ECDSA_SHA3_256 || mechanism == CKM_ECDSA_SHA3_384 || mechanism == CKM_ECDSA_SHA3_512) {
      return dsaAndEcdsaSign(content, hashAlgo);
    } else if (mechanism == CKM_VENDOR_SM2_SM3) {
      return sm2Sign(parameters, content);
    } else if (mechanism == CKM_DSA_SHA1 || mechanism == CKM_DSA_SHA224   || mechanism == CKM_DSA_SHA256
        || mechanism == CKM_DSA_SHA384   || mechanism == CKM_DSA_SHA512   || mechanism == CKM_DSA_SHA3_224
        || mechanism == CKM_DSA_SHA3_256 || mechanism == CKM_DSA_SHA3_384 || mechanism == CKM_DSA_SHA3_512) {
      return dsaAndEcdsaSign(content, hashAlgo);
    } else if (mechanism == CKM_SHA1_RSA_PKCS  || mechanism == CKM_SHA224_RSA_PKCS || mechanism == CKM_SHA256_RSA_PKCS
        || mechanism == CKM_SHA384_RSA_PKCS    || mechanism == CKM_SHA512_RSA_PKCS || mechanism == CKM_SHA3_224_RSA_PKCS
        || mechanism == CKM_SHA3_256_RSA_PKCS  || mechanism == CKM_SHA3_384_RSA_PKCS
        || mechanism == CKM_SHA3_512_RSA_PKCS) {
      return rsaPkcsSign(content, hashAlgo);
    } else if (mechanism == CKM_SHA1_RSA_PKCS_PSS || mechanism == CKM_SHA224_RSA_PKCS_PSS
        || mechanism == CKM_SHA256_RSA_PKCS_PSS   || mechanism == CKM_SHA384_RSA_PKCS_PSS
        || mechanism == CKM_SHA512_RSA_PKCS_PSS   || mechanism == CKM_SHA3_224_RSA_PKCS_PSS
        || mechanism == CKM_SHA3_256_RSA_PKCS_PSS || mechanism == CKM_SHA3_384_RSA_PKCS_PSS
        || mechanism == CKM_SHA3_512_RSA_PKCS_PSS) {
      return rsaPkcsPssSign(parameters, content, hashAlgo);
    } else if (mechanism == CKM_SHA_1_HMAC || mechanism == CKM_SHA224_HMAC   || mechanism == CKM_SHA256_HMAC
        || mechanism == CKM_SHA384_HMAC    || mechanism == CKM_SHA512_HMAC   || mechanism == CKM_SHA3_224_HMAC
        || mechanism == CKM_SHA3_256_HMAC  || mechanism == CKM_SHA3_384_HMAC || mechanism == CKM_SHA3_512_HMAC) {
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

  private byte[] aesGmac(P11Params params, byte[] contentToSign) throws P11TokenException {
    if (params == null) {
      throw new P11TokenException("iv may not be null");
    }

    byte[] iv;
    if (params instanceof P11Params.P11ByteArrayParams) {
      iv = ((P11Params.P11ByteArrayParams) params).getBytes();
    } else {
      throw new P11TokenException("params must be instanceof P11ByteArrayParams");
    }

    GMac gmac = new GMac(new GCMBlockCipher(new AESEngine()));
    gmac.init(new ParametersWithIV(new KeyParameter(signingKey.getEncoded()), iv));
    gmac.update(contentToSign, 0, contentToSign.length);
    byte[] signature = new byte[gmac.getMacSize()];
    gmac.doFinal(signature, 0);
    return signature;
  } // method aesGmac

  private byte[] rsaPkcsPssSign(P11Params parameters, byte[] contentToSign, HashAlgo hashAlgo)
      throws P11TokenException {
    if (!(parameters instanceof P11Params.P11RSAPkcsPssParams)) {
      throw new P11TokenException("the parameters is not of " + P11Params.P11RSAPkcsPssParams.class.getName());
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
      throw new P11TokenException("unsupported MaskGenerationFunction " + pssParam.getHashAlgorithm());
    }

    byte[] hashValue = (hashAlgo == null) ? contentToSign : hashAlgo.hash(contentToSign);
    byte[] encodedHashValue;
    try {
      encodedHashValue = PKCS1Util.EMSA_PSS_ENCODE(contentHash, hashValue, mgfHash,
          (int) pssParam.getSaltLength(), getExpectedSignatureLen() * 8, random);
    } catch (XiSecurityException ex) {
      throw new P11TokenException("XiSecurityException: " + ex.getMessage(), ex);
    }
    return rsaX509Sign(encodedHashValue);
  } // method rsaPkcsPssSign

  private byte[] rsaPkcsSign(byte[] contentToSign, HashAlgo hashAlgo) throws P11TokenException {
    int modulusBitLen = getExpectedSignatureLen() * 8;
    byte[] paddedHash;
    try {
      paddedHash = (hashAlgo == null) ? PKCS1Util.EMSA_PKCS1_v1_5_encoding(contentToSign, modulusBitLen)
          : PKCS1Util.EMSA_PKCS1_v1_5_encoding(hashAlgo.hash(contentToSign), modulusBitLen, hashAlgo);
    } catch (XiSecurityException ex) {
      throw new P11TokenException("XiSecurityException: " + ex.getMessage(), ex);
    }

    return rsaX509Sign(paddedHash);
  } // method rsaPkcsSign

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
  } // method rsaX509Sign

  private byte[] dsaAndEcdsaSign(byte[] dataToSign, HashAlgo hashAlgo) throws P11TokenException {
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
      return SignerUtil.dsaSigX962ToPlain(x962Signature, getExpectedSignatureLen() * 8);
    } catch (SignatureException ex) {
      throw new P11TokenException("SignatureException: " + ex.getMessage(), ex);
    } catch (XiSecurityException ex) {
      throw new P11TokenException("XiSecurityException: " + ex.getMessage(), ex);
    } finally {
      dsaSignatures.requite(sig0);
    }
  } // method dsaAndEcdsaSign

  private byte[] eddsaSign(byte[] dataToSign) throws P11TokenException {
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

  private byte[] sm2SignHash(byte[] hash) throws P11TokenException {
    ConcurrentBagEntry<EmulatorSM2Signer> sig0;
    try {
      sig0 = sm2Signers.borrow(5000, TimeUnit.MILLISECONDS);
    } catch (InterruptedException ex) {
      throw new P11TokenException("InterruptedException occurs while retrieving idle signature");
    }

    if (sig0 == null) {
      throw new P11TokenException("no idle SM2 Signer available");
    }

    try {
      EmulatorSM2Signer sig = sig0.value();
      byte[] x962Signature = sig.generateSignatureForHash(hash);
      return SignerUtil.dsaSigX962ToPlain(x962Signature, getExpectedSignatureLen() * 8);
    } catch (CryptoException ex) {
      throw new P11TokenException("CryptoException: " + ex.getMessage(), ex);
    } catch (XiSecurityException ex) {
      throw new P11TokenException("XiSecurityException: " + ex.getMessage(), ex);
    } finally {
      sm2Signers.requite(sig0);
    }
  } // method sm2SignHash

  private byte[] sm2Sign(P11Params params, byte[] dataToSign) throws P11TokenException {
    if (params == null) {
      throw new P11TokenException("userId may not be null");
    }

    byte[] userId;
    if (params instanceof P11Params.P11ByteArrayParams) {
      userId = ((P11Params.P11ByteArrayParams) params).getBytes();
    } else {
      throw new P11TokenException("params must be instanceof P11ByteArrayParams");
    }

    ConcurrentBagEntry<EmulatorSM2Signer> sig0;
    try {
      sig0 = sm2Signers.borrow(5000, TimeUnit.MILLISECONDS);
    } catch (InterruptedException ex) {
      throw new P11TokenException("InterruptedException occurs while retrieving idle signature");
    }

    if (sig0 == null) {
      throw new P11TokenException("no idle SM2 Signer available");
    }

    try {
      EmulatorSM2Signer sig = sig0.value();

      byte[] x962Signature = sig.generateSignatureForMessage(userId, dataToSign);
      return SignerUtil.dsaSigX962ToPlain(x962Signature, getExpectedSignatureLen() * 8);
    } catch (CryptoException ex) {
      throw new P11TokenException("CryptoException: " + ex.getMessage(), ex);
    } catch (XiSecurityException ex) {
      throw new P11TokenException("XiSecurityException: " + ex.getMessage(), ex);
    } finally {
      sm2Signers.requite(sig0);
    }
  } // method sm2Sign

}
