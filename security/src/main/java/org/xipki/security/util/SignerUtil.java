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

package org.xipki.security.util;

import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.range;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcDSAContentVerifierProviderBuilder;
import org.xipki.security.DHSigStaticKeyCertPair;
import org.xipki.security.HashAlgo;
import org.xipki.security.ObjectIdentifiers.Shake;
import org.xipki.security.XiSecurityException;
import org.xipki.security.bc.ShakePSSSigner;
import org.xipki.security.bc.XiECContentVerifierProviderBuilder;
import org.xipki.security.bc.XiEdDSAContentVerifierProvider;
import org.xipki.security.bc.XiRSAContentVerifierProviderBuilder;
import org.xipki.security.bc.XiShakeDigest;
import org.xipki.security.bc.XiXDHContentVerifierProvider;
import org.xipki.util.Hex;

/**
 * utility class for converting java.security RSA objects into their
 * org.bouncycastle.crypto counterparts.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignerUtil {

  private static final Map<HashAlgo, byte[]> digestPkcsPrefix = new HashMap<>();

  private static final DigestAlgorithmIdentifierFinder DIGESTALG_IDENTIFIER_FINDER
      = new DefaultDigestAlgorithmIdentifierFinder();

  private static final Map<String, BcContentVerifierProviderBuilder> VERIFIER_PROVIDER_BUILDER =
      new HashMap<>();

  static {
    addDigestPkcsPrefix(HashAlgo.SHA1,     "3021300906052b0e03021a05000414");
    addDigestPkcsPrefix(HashAlgo.SHA224,   "302d300d06096086480165030402040500041c");
    addDigestPkcsPrefix(HashAlgo.SHA256,   "3031300d060960864801650304020105000420");
    addDigestPkcsPrefix(HashAlgo.SHA384,   "3041300d060960864801650304020205000430");
    addDigestPkcsPrefix(HashAlgo.SHA512,   "3051300d060960864801650304020305000440");
    addDigestPkcsPrefix(HashAlgo.SHA3_224, "302d300d06096086480165030402070500041c");
    addDigestPkcsPrefix(HashAlgo.SHA3_256, "3031300d060960864801650304020805000420");
    addDigestPkcsPrefix(HashAlgo.SHA3_384, "3041300d060960864801650304020905000430");
    addDigestPkcsPrefix(HashAlgo.SHA3_512, "3051300d060960864801650304020a05000440");
  } // method static

  private static void addDigestPkcsPrefix(HashAlgo algo, String prefix) {
    digestPkcsPrefix.put(algo, Hex.decode(prefix));
  }

  private SignerUtil() {
  }

  // CHECKSTYLE:SKIP
  public static RSAKeyParameters generateRSAPrivateKeyParameter(RSAPrivateKey key) {
    notNull(key, "key");
    if (key instanceof RSAPrivateCrtKey) {
      RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;

      return new RSAPrivateCrtKeyParameters(rsaKey.getModulus(), rsaKey.getPublicExponent(),
          rsaKey.getPrivateExponent(), rsaKey.getPrimeP(), rsaKey.getPrimeQ(),
          rsaKey.getPrimeExponentP(), rsaKey.getPrimeExponentQ(), rsaKey.getCrtCoefficient());
    } else {
      return new RSAKeyParameters(true, key.getModulus(), key.getPrivateExponent());
    }
  }

  // CHECKSTYLE:SKIP
  public static Signer createPSSRSASigner(AlgorithmIdentifier sigAlgId)
      throws XiSecurityException {
    return createPSSRSASigner(sigAlgId, null);
  }

  // CHECKSTYLE:SKIP
  public static Signer createPSSRSASigner(AlgorithmIdentifier sigAlgId,
      AsymmetricBlockCipher cipher)
          throws XiSecurityException {
    notNull(sigAlgId, "sigAlgId");
    ASN1ObjectIdentifier oid = sigAlgId.getAlgorithm();

    AsymmetricBlockCipher tmpCipher = (cipher == null) ? new RSABlindedEngine() : cipher;

    if (Shake.id_RSASSA_PSS_SHAKE128.equals(oid)
        || Shake.id_RSASSA_PSS_SHAKE256.equals(oid)) {
      XiShakeDigest dig;
      if (Shake.id_RSASSA_PSS_SHAKE128.equals(oid)) {
        dig = (XiShakeDigest) HashAlgo.SHAKE128.createDigest();
      } else {
        dig = (XiShakeDigest) HashAlgo.SHAKE256.createDigest();
      }

      return new ShakePSSSigner(tmpCipher, dig);
    } else if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(oid)) {
      AlgorithmIdentifier digAlgId;
      try {
        digAlgId = AlgorithmUtil.extractDigesetAlgFromSigAlg(sigAlgId);
      } catch (NoSuchAlgorithmException ex) {
        throw new XiSecurityException(ex.getMessage(), ex);
      }

      RSASSAPSSparams param = RSASSAPSSparams.getInstance(sigAlgId.getParameters());

      AlgorithmIdentifier mfgDigAlgId = AlgorithmIdentifier.getInstance(
          param.getMaskGenAlgorithm().getParameters());

      Digest dig = getDigest(digAlgId);
      Digest mgfDig = getDigest(mfgDigAlgId);

      int saltSize = param.getSaltLength().intValue();
      int trailerField = param.getTrailerField().intValue();
      return new PSSSigner(tmpCipher, dig, mgfDig, saltSize, getTrailer(trailerField));
    } else {
      throw new XiSecurityException("signature algorithm " + oid
          + " is not allowed");
    }
  } // method createPSSRSASigner

  private static byte getTrailer(int trailerField) {
    if (trailerField == 1) {
      return org.bouncycastle.crypto.signers.PSSSigner.TRAILER_IMPLICIT;
    }

    throw new IllegalArgumentException("unknown trailer field");
  }

  // CHECKSTYLE:SKIP
  public static byte[] EMSA_PKCS1_v1_5_encoding(byte[] hashValue, int modulusBigLength,
      HashAlgo hashAlgo)
          throws XiSecurityException {
    notNull(hashValue, "hashValue");
    notNull(hashAlgo, "hashAlgo");

    final int hashLen = hashAlgo.getLength();
    range(hashValue.length, "hashValue.length", hashLen, hashLen);

    int blockSize = (modulusBigLength + 7) / 8;
    byte[] prefix = digestPkcsPrefix.get(hashAlgo);

    if (prefix.length + hashLen + 3 > blockSize) {
      throw new XiSecurityException("data too long (maximal " + (blockSize - 3)
          + " allowed): " + (prefix.length + hashLen));
    }

    byte[] block = new byte[blockSize];

    block[0] = 0x00;
    // type code 1
    block[1] = 0x01;

    int offset = 2;
    while (offset < block.length - prefix.length - hashLen - 1) {
      block[offset++] = (byte) 0xFF;
    }
    // mark the end of the padding
    block[offset++] = 0x00;

    System.arraycopy(prefix, 0, block, offset, prefix.length);
    offset += prefix.length;
    System.arraycopy(hashValue, 0, block, offset, hashValue.length);
    return block;
  } // method EMSA_PKCS1_v1_5_encoding

  // CHECKSTYLE:SKIP
  public static byte[] EMSA_PKCS1_v1_5_encoding(byte[] encodedDigestInfo, int modulusBigLength)
      throws XiSecurityException {
    notNull(encodedDigestInfo, "encodedDigestInfo");

    int msgLen = encodedDigestInfo.length;
    int blockSize = (modulusBigLength + 7) / 8;

    if (msgLen + 3 > blockSize) {
      throw new XiSecurityException("data too long (maximal " + (blockSize - 3)
          + " allowed): " + msgLen);
    }

    byte[] block = new byte[blockSize];

    block[0] = 0x00;
    // type code 1
    block[1] = 0x01;

    int offset = 2;
    while (offset < block.length - msgLen - 1) {
      block[offset++] = (byte) 0xFF;
    }
    // mark the end of the padding
    block[offset++] = 0x00;

    System.arraycopy(encodedDigestInfo, 0, block, offset, encodedDigestInfo.length);
    return block;
  } // method EMSA_PKCS1_v1_5_encoding

  // CHECKSTYLE:SKIP
  public static byte[] EMSA_PSS_ENCODE(HashAlgo contentDigest, byte[] hashValue, HashAlgo mgfDigest,
      int saltLen, int modulusBitLength, SecureRandom random)
          throws XiSecurityException {
    switch (contentDigest) {
      case SHAKE128:
      case SHAKE256:
        if (mgfDigest != contentDigest) {
          throw new XiSecurityException("contentDigest != mgfDigest");
        }

        if (saltLen != contentDigest.getLength()) {
          throw new XiSecurityException("saltLen != " + contentDigest.getLength() + ": " + saltLen);
        }
        break;
      default:
        break;
    }

    final int hLen = contentDigest.getLength();
    final byte[] salt = new byte[saltLen];
    final byte[] mDash = new byte[8 + saltLen + hLen];
    final byte trailer = (byte)0xBC;

    if (hashValue.length != hLen) {
      throw new XiSecurityException("hashValue.length is incorrect: "
          + hashValue.length + " != " + hLen);
    }

    int emBits = modulusBitLength - 1;
    if (emBits < (8 * hLen + 8 * saltLen + 9)) {
      throw new IllegalArgumentException("key too small for specified hash and salt lengths");
    }

    System.arraycopy(hashValue, 0, mDash, mDash.length - hLen - saltLen, hLen);

    random.nextBytes(salt);
    System.arraycopy(salt, 0, mDash, mDash.length - saltLen, saltLen);

    byte[] hv = contentDigest.hash(mDash);
    byte[] block = new byte[(emBits + 7) / 8];
    block[block.length - saltLen - 1 - hLen - 1] = 0x01;
    System.arraycopy(salt, 0, block, block.length - saltLen - hLen - 1, saltLen);

    byte[] dbMask;
    int dbMaskLen = block.length - hLen - 1;
    switch (contentDigest) {
      case SHAKE128:
      case SHAKE256:
        XiShakeDigest digest = (XiShakeDigest) contentDigest.createDigest();
        dbMask = digest.maskGeneratorFunction(hv, dbMaskLen);
        break;
      default:
        dbMask = maskGeneratorFunction1(mgfDigest, hv, dbMaskLen);
        break;
    }

    for (int i = 0; i != dbMask.length; i++) {
      block[i] ^= dbMask[i];
    }

    block[0] &= (0xff >> ((block.length * 8) - emBits));

    System.arraycopy(hv, 0, block, block.length - hLen - 1, hLen);

    block[block.length - 1] = trailer;
    return block;
  } // method EMSA_PSS_ENCODE

  /**
   * int to octet string.
   */
  private static void ItoOSP(int i, byte[] sp, int spOffset) { // CHECKSTYLE:SKIP
    sp[spOffset    ] = (byte)(i >>> 24);
    sp[spOffset + 1] = (byte)(i >>> 16);
    sp[spOffset + 2] = (byte)(i >>> 8);
    sp[spOffset + 3] = (byte)(i);
  }

  /**
   * mask generator function, as described in PKCS1v2.
   */
  // CHECKSTYLE:SKIP
  private static byte[] maskGeneratorFunction1(HashAlgo mgfDigest, byte[] Z, int length) {
    int mgfhLen = mgfDigest.getLength();
    byte[] mask = new byte[length];
    int counter = 0;

    byte[] all = new byte[Z.length + 4];
    System.arraycopy(Z, 0, all, 0, Z.length);

    while (counter < (length / mgfhLen)) {
      ItoOSP(counter, all, Z.length);
      byte[] hashBuf = mgfDigest.hash(all);
      System.arraycopy(hashBuf, 0, mask, counter * mgfhLen, mgfhLen);
      counter++;
    }

    if ((counter * mgfhLen) < length) {
      ItoOSP(counter, all, Z.length);
      byte[] hashBuf = mgfDigest.hash(all);
      int offset = counter * mgfhLen;
      System.arraycopy(hashBuf, 0, mask, offset, mask.length - offset);
    }

    return mask;
  } // method maskGeneratorFunction1

  // CHECKSTYLE:SKIP
  public static byte[] dsaSigPlainToX962(byte[] signature)
      throws XiSecurityException {
    notNull(signature, "signature");
    if (signature.length % 2 != 0) {
      throw new XiSecurityException("signature.lenth must be even, but is odd");
    }
    byte[] ba = new byte[signature.length / 2];
    ASN1EncodableVector sigder = new ASN1EncodableVector();

    System.arraycopy(signature, 0, ba, 0, ba.length);
    sigder.add(new ASN1Integer(new BigInteger(1, ba)));

    System.arraycopy(signature, ba.length, ba, 0, ba.length);
    sigder.add(new ASN1Integer(new BigInteger(1, ba)));

    DERSequence seq = new DERSequence(sigder);
    try {
      return seq.getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("IOException, message: " + ex.getMessage(), ex);
    }
  } // method dsaSigPlainToX962

  // CHECKSTYLE:SKIP
  public static byte[] dsaSigX962ToPlain(byte[] x962Signature, int keyBitLen)
      throws XiSecurityException {
    notNull(x962Signature, "x962Signature");
    ASN1Sequence seq = ASN1Sequence.getInstance(x962Signature);
    if (seq.size() != 2) {
      throw new IllegalArgumentException("invalid X962Signature");
    }
    BigInteger sigR = ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue();
    BigInteger sigS = ASN1Integer.getInstance(seq.getObjectAt(1)).getPositiveValue();
    return dsaSigToPlain(sigR, sigS, keyBitLen);
  } // method dsaSigX962ToPlain

  public static byte[] dsaSigToPlain(BigInteger sigR, BigInteger sigS, int keyBitLen)
      throws XiSecurityException {
    notNull(sigR, "sigR");
    notNull(sigS, "sigS");

    final int blockSize = (keyBitLen + 7) / 8;
    int bitLenOfR = sigR.bitLength();
    int bitLenOfS = sigS.bitLength();
    int bitLen = Math.max(bitLenOfR, bitLenOfS);
    if ((bitLen + 7) / 8 > blockSize) {
      throw new XiSecurityException("signature is too large");
    }

    byte[] plainSignature = new byte[2 * blockSize];
    bigIntToBytes(sigR, plainSignature, 0, blockSize);
    bigIntToBytes(sigS, plainSignature, blockSize, blockSize);
    return plainSignature;
  } // method dsaSigToPlain

  private static void bigIntToBytes(BigInteger num, byte[] dest, int destPos, int length) {
    byte[] bytes = num.toByteArray();
    if (bytes.length == length) {
      System.arraycopy(bytes, 0, dest, destPos, length);
    } else if (bytes.length < length) {
      System.arraycopy(bytes, 0, dest, destPos + length - bytes.length, bytes.length);
    } else {
      System.arraycopy(bytes, bytes.length - length, dest, destPos, length);
    }
  } // method bigIntToBytes

  private static Digest getDigest(AlgorithmIdentifier hashAlgId)
      throws XiSecurityException {
    return getDigest(hashAlgId.getAlgorithm());
  }

  private static Digest getDigest(ASN1ObjectIdentifier hashAlgOid)
      throws XiSecurityException {
    HashAlgo hat = HashAlgo.getInstance(hashAlgOid);
    if (hat != null) {
      return hat.createDigest();
    } else {
      throw new XiSecurityException("could not get digest for " + hashAlgOid.getId());
    }
  }

  public static byte[] getDigestPkcsPrefix(HashAlgo hashAlgo) {
    byte[] bytes = digestPkcsPrefix.get(hashAlgo);
    return (bytes == null) ? null : Arrays.copyOf(bytes, bytes.length);
  }

  public static ContentVerifierProvider getContentVerifierProvider(PublicKey publicKey,
      DHSigStaticKeyCertPair ownerKeyAndCert)
          throws InvalidKeyException {
    notNull(publicKey, "publicKey");

    String keyAlg = publicKey.getAlgorithm().toUpperCase();
    if ("ED25519".equals(keyAlg) || "ED448".equals(keyAlg)) {
      return new XiEdDSAContentVerifierProvider(publicKey);
    } else if ("X25519".equals(keyAlg) || "X448".equals(keyAlg)) {
      if (ownerKeyAndCert == null) {
        throw new InvalidKeyException("ownerKeyAndCert is required but absent");
      }
      return new XiXDHContentVerifierProvider(publicKey, ownerKeyAndCert);
    }

    BcContentVerifierProviderBuilder builder = VERIFIER_PROVIDER_BUILDER.get(keyAlg);

    if (builder == null) {
      if ("RSA".equals(keyAlg)) {
        builder = new XiRSAContentVerifierProviderBuilder();
      } else if ("DSA".equals(keyAlg)) {
        builder = new BcDSAContentVerifierProviderBuilder(DIGESTALG_IDENTIFIER_FINDER);
      } else if ("EC".equals(keyAlg) || "ECDSA".equals(keyAlg)) {
        builder = new XiECContentVerifierProviderBuilder();
      } else {
        throw new InvalidKeyException("unknown key algorithm of the public key " + keyAlg);
      }
      VERIFIER_PROVIDER_BUILDER.put(keyAlg, builder);
    }

    AsymmetricKeyParameter keyParam = KeyUtil.generatePublicKeyParameter(publicKey);
    try {
      return builder.build(keyParam);
    } catch (OperatorCreationException ex) {
      throw new InvalidKeyException("could not build ContentVerifierProvider: "
          + ex.getMessage(), ex);
    }
  } // method getContentVerifierProvider

}
