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

package org.xipki.ca.server.cmp;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.operator.OperatorException;
import org.xipki.security.HashAlgo;
import org.xipki.security.ObjectIdentifiers;

import javax.crypto.Cipher;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * CRMF key wrapper.
 *
 * @author Lijun Liao
 */

abstract class CrmfKeyWrapper {

  abstract AlgorithmIdentifier getAlgorithmIdentifier();

  abstract byte[] generateWrappedKey(byte[] encryptionKey)
      throws OperatorException;

  // CHECKSTYLE:SKIP
  static class RSAOAEPAsymmetricKeyWrapper extends CrmfKeyWrapper {

    private static final AlgorithmIdentifier OAEP_DFLT = new AlgorithmIdentifier(
        PKCSObjectIdentifiers.id_RSAES_OAEP, new RSAESOAEPparams());

    private final PublicKey publicKey;

    public RSAOAEPAsymmetricKeyWrapper(PublicKey publicKey) {
      this.publicKey = publicKey;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return OAEP_DFLT;
    }

    @Override
    public byte[] generateWrappedKey(byte[] encryptionKey)
        throws OperatorException {
      try {
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPPADDING", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(encryptionKey);
      } catch (Exception ex) {
        throw new OperatorException("error in generateWrappedKey", ex);
      }
    } // method generateWrappedKey

  } // class RSAOAEPAsymmetricKeyWrapper

  // CHECKSTYLE:SKIP
  static class ECIESAsymmetricKeyWrapper extends CrmfKeyWrapper {

    private final AlgorithmIdentifier algorithmIdentifier;

    private static final int ephemeralPublicKeyLen = 65; // 1 (04)+ 32 (Qx) + 32 (Qy)

    private static final int macLen = 20; // SHA1

    private static final int aesKeySize = 128;

    private final PublicKey publicKey;

    public ECIESAsymmetricKeyWrapper(PublicKey publicKey) {
      this.publicKey = publicKey;
      this.algorithmIdentifier = new AlgorithmIdentifier(
          ObjectIdentifiers.Secg.id_ecies_specifiedParameters, buildECIESParameters());
    } // constructor

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algorithmIdentifier;
    }

    /**
     * Encrypt the key with the following output.
     * <pre>
     * ECIES-Ciphertext-Value ::= SEQUENCE {
     *     ephemeralPublicKey ECPoint,
     *     symmetricCiphertext OCTET STRING,
     *     macTag OCTET STRING
     * }
     *
     * ECPoint ::= OCTET STRING
     * </pre>
     */
    @Override
    public byte[] generateWrappedKey(byte[] keyToWrap)
        throws OperatorException {
      try {
        BlockCipher cbcCipher = new CBCBlockCipher(new AESEngine());
        IESCipher cipher = new IESCipher(
            new IESEngine(new ECDHBasicAgreement(),
                new KDF2BytesGenerator(new SHA1Digest()),
                new HMac(new SHA1Digest()),
                new PaddedBufferedBlockCipher(cbcCipher)), 16);

        // According to the §3.8 in SEC 1, Version 2.0:
        // "Furthermore here the 16 octet or 128 bit IV for AES in CBC mode should always take
        //  the value 0000000000000000_{16}"
        byte[] iv = new byte[16];
        IESParameterSpec spec = new IESParameterSpec(null, null, aesKeySize, aesKeySize, iv);
        cipher.engineInit(Cipher.ENCRYPT_MODE, publicKey, spec, new SecureRandom());
        byte[] bcResult = cipher.engineDoFinal(keyToWrap, 0, keyToWrap.length);
        // convert the result to ASN.1 format
        ASN1Encodable[] array = new ASN1Encodable[3];
        // ephemeralPublicKey ECPoint
        byte[] ephemeralPublicKey = new byte[ephemeralPublicKeyLen];

        System.arraycopy(bcResult, 0, ephemeralPublicKey, 0, ephemeralPublicKeyLen);
        array[0] = new DEROctetString(ephemeralPublicKey);

        // symmetricCiphertext OCTET STRING
        int symmetricCiphertextLen = bcResult.length - ephemeralPublicKeyLen - macLen;
        byte[] symmetricCiphertext = new byte[symmetricCiphertextLen];
        System.arraycopy(bcResult, ephemeralPublicKeyLen,
            symmetricCiphertext, 0, symmetricCiphertextLen);
        array[1] = new DEROctetString(symmetricCiphertext);

        // macTag OCTET STRING
        byte[] macTag = new byte[macLen];
        System.arraycopy(bcResult, ephemeralPublicKeyLen + symmetricCiphertextLen,
            macTag, 0, macLen);
        array[2] = new DEROctetString(macTag);
        return new DERSequence(array).getEncoded();
      } catch (Exception ex) {
        throw new OperatorException("error while generateWrappedKey", ex);
      }
    } // method generateWrappedKey

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
          ObjectIdentifiers.Misc.id_iso18033_kdf2, new AlgorithmIdentifier(HashAlgo.SHA1.getOid()));
      vec.add(new DERTaggedObject(true, 0, keyDerivationFunction));

      // SymmetricEncryption
      AlgorithmIdentifier symmetricEncryption = new AlgorithmIdentifier(
          ObjectIdentifiers.Secg.id_aes128_cbc_in_ecies);
      vec.add(new DERTaggedObject(true, 1, symmetricEncryption));

      // MessageAuthenticationCode
      AlgorithmIdentifier mac = new AlgorithmIdentifier(ObjectIdentifiers.Secg.id_hmac_full_ecies,
          new AlgorithmIdentifier(HashAlgo.SHA1.getOid()));
      vec.add(new DERTaggedObject(true, 2, mac));
      return new DERSequence(vec);
    } // method buildECIESParameters

  } // class ECIESAsymmetricKeyWrapper

}
