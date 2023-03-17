// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11.emulator;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.generators.SCrypt;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.EdECConstants;
import org.xipki.util.StringUtil;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import static org.xipki.util.Args.notNull;

/**
 * Encrypts and decrypts private key in the emulator.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class EmulatorKeyCryptor {

  /**
   * KeyDerive: SCRYPT (S = 0x0000000000000000 (8 bytes), N = 16384, r = 8, p = 1) and
   * AES_GCM_NoPadding with 128-bit key.
   */
  private static final byte ALG_SCRYPT1_AESGCMNopadding_128 = 1;

  private static final int AES_GCM_NONCE_BYTE_SIZE = 12;

  private static final int AES_GCM_TAG_BIT_SIZE = 16 * 8;

  private final SecretKey key;

  private final SecureRandom rnd;

  EmulatorKeyCryptor(char[] password) {
    notNull(password, "password");

    /*
     * @param P     the bytes of the pass phrase.
     * @param S     the salt to use for this invocation.
     * @param N     CPU/Memory cost parameter. Must be larger than 1, a power of 2 and less than
     *              <code>2^(128 * r / 8)</code>.
     * @param r     the block size, must be &gt;= 1.
     * @param p     Parallelization parameter. Must be a positive integer less than or equal to
     *              <code>Integer.MAX_VALUE / (128 * r * 8)</code>.
     * @param dkLen the length of the key to generate.
     */
    byte[] P = StringUtil.toUtf8Bytes(new String(password)); // password
    byte[] S = new byte[8];
    byte[] dkey = SCrypt.generate(P, S, 16384, 8, 1, 16); //N: 16384, r: 8, p: 1, dkLen: 16
    this.key = new SecretKeySpec(dkey, "AES");

    this.rnd = new SecureRandom();
  } // constructor

  PrivateKey decryptPrivateKey(byte[] encryptedPrivateKeyInfo) throws TokenException {
    notNull(encryptedPrivateKeyInfo, "encryptedPrivateKeyInfo");
    byte[] plain = decrypt(encryptedPrivateKeyInfo);

    PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(plain);
    AlgorithmIdentifier keyAlg = privateKeyInfo.getPrivateKeyAlgorithm();
    ASN1ObjectIdentifier keyAlgOid = keyAlg.getAlgorithm();

    String algoName;
    if (PKCSObjectIdentifiers.rsaEncryption.equals(keyAlgOid)) {
      algoName = "RSA";
    } else if (X9ObjectIdentifiers.id_dsa.equals(keyAlgOid)) {
      algoName = "DSA";
    } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(keyAlgOid)) {
      algoName = "EC";
    } else {
      algoName = EdECConstants.getName(keyAlg.getAlgorithm());
    }

    if (algoName == null) {
      throw new TokenException("unknown private key algorithm " + keyAlgOid.getId());
    }

    try {
      KeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());
      KeyFactory keyFactory = KeyFactory.getInstance(algoName, "BC");
      return keyFactory.generatePrivate(keySpec);
    } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException ex) {
      throw new TokenException(ex.getClass().getName() + ": " + ex.getMessage(), ex);
    }
  } // method decryptPrivateKey

  byte[] decrypt(byte[] cipherBlob) throws TokenException {
    notNull(cipherBlob, "cipherBlob");

    if (cipherBlob[0] != ALG_SCRYPT1_AESGCMNopadding_128) {
      throw new TokenException("unknown encryption algorithm");
    }

    GCMParameterSpec spec = new GCMParameterSpec(AES_GCM_TAG_BIT_SIZE, cipherBlob, 1, AES_GCM_NONCE_BYTE_SIZE);

    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      cipher.init(Cipher.DECRYPT_MODE, key, spec);

      int cipherValueOffset = 1 + AES_GCM_NONCE_BYTE_SIZE;
      final int cipherLen = cipherBlob.length - cipherValueOffset;
      int plainLen = cipher.getOutputSize(cipherLen);
      byte[] plain = new byte[plainLen];
      int realPlainLen = cipher.doFinal(cipherBlob, cipherValueOffset, cipherLen, plain, 0);
      if (plainLen > realPlainLen) {
        plain = Arrays.copyOf(plain, realPlainLen);
      }

      return plain;
    } catch (GeneralSecurityException ex) {
      throw new TokenException(ex);
    }
  } // method decrypt

  byte[] encrypt(PrivateKey privateKey) throws TokenException {
    return encrypt(notNull(privateKey, "privateKey").getEncoded());
  }

  byte[] encrypt(SecretKey secretKey) throws TokenException {
    return encrypt(secretKey.getEncoded());
  }

  byte[] encrypt(byte[] data) throws TokenException {
    byte[] nonce = new byte[AES_GCM_NONCE_BYTE_SIZE];
    rnd.nextBytes(nonce);
    GCMParameterSpec spec = new GCMParameterSpec(AES_GCM_TAG_BIT_SIZE, nonce);

    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      cipher.init(Cipher.ENCRYPT_MODE, key, spec);

      int cipherLen = cipher.getOutputSize(data.length);
      byte[] cipherBlob = new byte[1 + nonce.length + cipherLen];
      cipherBlob[0] = ALG_SCRYPT1_AESGCMNopadding_128;
      System.arraycopy(nonce, 0, cipherBlob, 1, nonce.length);

      int offset = 1 + nonce.length;
      int realCipherLen = cipher.doFinal(data, 0, data.length, cipherBlob, offset);
      return (cipherLen == realCipherLen) ? cipherBlob : Arrays.copyOf(cipherBlob, offset + realCipherLen);
    } catch (GeneralSecurityException ex) {
      throw new TokenException(ex);
    }
  }

}
