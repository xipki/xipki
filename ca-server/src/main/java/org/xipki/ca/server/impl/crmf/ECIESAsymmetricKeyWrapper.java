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

package org.xipki.ca.server.impl.crmf;

import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.KeyWrapper;
import org.bouncycastle.operator.OperatorException;
import org.xipki.security.HashAlgo;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.util.KeyUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

// CHECKSTYLE:SKIP
public class ECIESAsymmetricKeyWrapper implements KeyWrapper {

  private AlgorithmIdentifier algorithmIdentifier;

  private PublicKey publicKey;

  private final int aesKeySize = 128;

  public ECIESAsymmetricKeyWrapper(PublicKey publicKey) {
    this.publicKey = publicKey;
    this.algorithmIdentifier = new AlgorithmIdentifier(
        ObjectIdentifiers.id_ecies_specifiedParameters, buildECIESParameters());
  }

  @Override
  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return algorithmIdentifier;
  }

  @Override
  public byte[] generateWrappedKey(GenericKey encryptionKey) throws OperatorException {
    try {
      Cipher cipher = Cipher.getInstance("ECIESWITHAES-CBC", "BC");
      // if not AES128, cipher must be initialized with IESParameterSpec which specifies the AES
      // keysize
      // According to the §3.8 in SEC 1, Version 2.0:
      // "Furthermore here the 16 octet or 128 bit IV for AES in CBC mode should always take
      //  the value 0000000000000000_{16}"
      byte[] iv = new byte[16];
      IESParameterSpec spec = new IESParameterSpec(null, null, aesKeySize, aesKeySize, iv);
      cipher.init(Cipher.ENCRYPT_MODE, publicKey, spec, new SecureRandom());
      byte[] encryptionKeyBytes = getKeyBytes(encryptionKey);
      return cipher.doFinal(encryptionKeyBytes);
    } catch (Exception ex) {
      throw new OperatorException("error while generateWrappedKey", ex);
    }
  }

  static byte[] getKeyBytes(GenericKey key) {
    if (key.getRepresentation() instanceof Key) {
      return ((Key)key.getRepresentation()).getEncoded();
    }

    if (key.getRepresentation() instanceof byte[]) {
      return (byte[])key.getRepresentation();
    }

    throw new IllegalArgumentException("unknown generic key type");
  }

  /**
   * <pre>
   * ECIESParameters ::= SEQUENCE {
   *     kdf [0] KeyDerivationFunction OPTIONAL,
   *     sym [1] SymmetricEncryption OPTIONAL,
   *     mac [2] MessageAuthenticationCode OPTIONAL
   * }
   *
   * KeyDerivationFunction ::= AlgorithmIdentifier {{ KDFSet }}
   * KDFSet ALGORITHM ::= {
   *    { OID x9-63-kdf PARMS HashAlgorithm } |
   *    { OID nist-concatenation-kdf PARMS HashAlgorithm } |
   *    { OID tls-kdf PARMS HashAlgorithm } |
   *    { OID ikev2-kdf PARMS HashAlgorithm } ,
   *    ... -- Future combinations may be added
   * }
   *
   * HashAlgorithm ::= AlgorithmIdentifier {{ HashFunctions }}
   * HashFunctions ALGORITHM ::= {
   *    { OID sha-1 PARMS NULL } |
   *    { OID id-sha224 PARMS NULL } |
   *    { OID id-sha256 PARMS NULL } |
   *    { OID id-sha384 PARMS NULL } |
   *    { OID id-sha512 PARMS NULL } ,
   *
   * SymmetricEncryption ::= AlgorithmIdentifier {{ SYMENCSet }}
   * MessageAuthenticationCode ::= AlgorithmIdentifier {{ MACSet }}
   * SYMENCSet ALGORITHM ::= {
   *    { OID xor-in-ecies } |
   *    { OID tdes-cbc-in-ecies } |
   *    { OID aes128-cbc-in-ecies } |
   *    { OID aes192-cbc-in-ecies } |
   *    { OID aes256-cbc-in-ecies } |
   *    { OID aes128-ctr-in-ecies } |
   *    { OID aes192-ctr-in-ecies } |
   *    { OID aes256-ctr-in-ecies } ,
   *    ... -- Future combinations may be added
   * }
   *
   * MACSet ALGORITHM ::= {
   *    { OID hmac-full-ecies PARMS HashAlgorithm } |
   *    { OID hmac-half-ecies PARMS HashAlgorithm } |
   *    { OID cmac-aes128-ecies } |
   *    { OID cmac-aes192-ecies } |
   *    { OID cmac-aes256-ecies } ,
   *    ... -- Future combinations may be added
   * }
   * </pre>
   */
  // CHECKSTYLE:SKIP
  private ASN1Sequence buildECIESParameters() {
    ASN1EncodableVector vec = new ASN1EncodableVector();
    // KeyDerivationFunction
    AlgorithmIdentifier keyDerivationFunction = new AlgorithmIdentifier(
        ObjectIdentifiers.id_iso18033_kdf2, new AlgorithmIdentifier(HashAlgo.SHA1.getOid()));
    vec.add(new DERTaggedObject(true, 0, keyDerivationFunction));

    // SymmetricEncryption
    AlgorithmIdentifier symmetricEncryption = new AlgorithmIdentifier(
        ObjectIdentifiers.id_aes128_cbc_in_ecies);
    vec.add(new DERTaggedObject(true, 1, symmetricEncryption));

    // MessageAuthenticationCode
    AlgorithmIdentifier mac = new AlgorithmIdentifier(ObjectIdentifiers.id_hmac_full_ecies,
        new AlgorithmIdentifier(HashAlgo.SHA1.getOid()));
    vec.add(new DERTaggedObject(true, 2, mac));
    return new DERSequence(vec);
  }

  public static void main(String[] args) {
    try {
      Security.addProvider(new BouncyCastleProvider());
      byte[] iv = new byte[16];
      Cipher cipher = Cipher.getInstance("ECIESWITHAES-CBC", "BC");
      KeyPair kp = KeyUtil.generateECKeypair(SECObjectIdentifiers.secp256r1, null);
      IESParameterSpec spec = new IESParameterSpec(null, null, 128, 128, iv);
      cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic(), spec, new SecureRandom());
      byte[] encryptionKeyBytes = new byte[] {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
      byte[] cipherValues = cipher.doFinal(encryptionKeyBytes);

      Cipher cipher2 = Cipher.getInstance("ECIESWITHAES-CBC", "BC");
      spec = new IESParameterSpec(null, null, 128, 128, iv);
      cipher2.init(Cipher.DECRYPT_MODE, kp.getPrivate(), spec, new SecureRandom());
      byte[] decryptedValues = cipher2.doFinal(cipherValues);

      System.out.println(Arrays.equals(encryptionKeyBytes, decryptedValues));
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

}

