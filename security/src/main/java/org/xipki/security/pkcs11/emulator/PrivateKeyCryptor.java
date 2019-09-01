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

package org.xipki.security.pkcs11.emulator;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.xipki.security.EdECConstants;
import org.xipki.security.pkcs11.P11TokenException;
import org.xipki.util.Args;

/**
 * Encrypts and decrypts private key in the emulator.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class PrivateKeyCryptor {
  private static final ASN1ObjectIdentifier ALGO =
      PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC;
  private static final int ITERATION_COUNT = 2048;

  private OutputEncryptor encryptor;
  private InputDecryptorProvider decryptorProvider;

  PrivateKeyCryptor(char[] password) throws P11TokenException {
    Args.notNull(password, "password");
    JcePKCSPBEOutputEncryptorBuilder eb = new JcePKCSPBEOutputEncryptorBuilder(ALGO);
    eb.setProvider("BC");
    eb.setIterationCount(ITERATION_COUNT);
    try {
      encryptor = eb.build(password);
    } catch (OperatorCreationException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }

    JcePKCSPBEInputDecryptorProviderBuilder db = new JcePKCSPBEInputDecryptorProviderBuilder();
    decryptorProvider = db.build(password);
  } // constructor

  PrivateKey decrypt(PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo)
      throws P11TokenException {
    Args.notNull(encryptedPrivateKeyInfo, "encryptedPrivateKeyInfo");
    PrivateKeyInfo privateKeyInfo;
    synchronized (decryptorProvider) {
      try {
        privateKeyInfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider);
      } catch (PKCSException ex) {
        throw new P11TokenException(ex.getMessage(), ex);
      }
    }

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
      throw new P11TokenException("unknown private key algorithm " + keyAlgOid.getId());
    }

    try {
      KeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());
      KeyFactory keyFactory = KeyFactory.getInstance(algoName, "BC");
      return keyFactory.generatePrivate(keySpec);
    } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException
        | InvalidKeySpecException ex) {
      throw new P11TokenException(ex.getClass().getName() + ": " + ex.getMessage(), ex);
    }
  } // method decrypt

  PKCS8EncryptedPrivateKeyInfo encrypt(PrivateKey privateKey) {
    Args.notNull(privateKey, "privateKey");
    PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
    PKCS8EncryptedPrivateKeyInfoBuilder builder = new PKCS8EncryptedPrivateKeyInfoBuilder(
        privateKeyInfo);
    synchronized (encryptor) {
      return builder.build(encryptor);
    }
  }

}
