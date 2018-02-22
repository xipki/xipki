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

package org.xipki.security.util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.xipki.common.util.Hex;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.HashAlgoType;
import org.xipki.security.exception.XiSecurityException;

/**
 * utility class for converting java.security RSA objects into their
 * org.bouncycastle.crypto counterparts.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignerUtil {

  private static final Map<HashAlgoType, byte[]> digestPkcsPrefix = new HashMap<>();

  static {
    addDigestPkcsPrefix(HashAlgoType.SHA1, "3021300906052b0e03021a05000414");
    addDigestPkcsPrefix(HashAlgoType.SHA224, "302d300d06096086480165030402040500041c");
    addDigestPkcsPrefix(HashAlgoType.SHA256, "3031300d060960864801650304020105000420");
    addDigestPkcsPrefix(HashAlgoType.SHA384, "3041300d060960864801650304020205000430");
    addDigestPkcsPrefix(HashAlgoType.SHA512, "3051300d060960864801650304020305000440");
    addDigestPkcsPrefix(HashAlgoType.SHA3_224, "302d300d06096086480165030402070500041c");
    addDigestPkcsPrefix(HashAlgoType.SHA3_256, "3031300d060960864801650304020805000420");
    addDigestPkcsPrefix(HashAlgoType.SHA3_384, "3041300d060960864801650304020905000430");
    addDigestPkcsPrefix(HashAlgoType.SHA3_512, "3051300d060960864801650304020a05000440");
  }

  private static void addDigestPkcsPrefix(HashAlgoType algo, String prefix) {
    digestPkcsPrefix.put(algo, Hex.decode(prefix));
  }

  private SignerUtil() {
  }

  // CHECKSTYLE:SKIP
  public static RSAKeyParameters generateRSAPrivateKeyParameter(RSAPrivateKey key) {
    ParamUtil.requireNonNull("key", key);
    if (key instanceof RSAPrivateCrtKey) {
      RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;

      return new RSAPrivateCrtKeyParameters(rsaKey.getModulus(), rsaKey.getPublicExponent(),
          rsaKey.getPrivateExponent(), rsaKey.getPrimeP(), rsaKey.getPrimeQ(),
          rsaKey.getPrimeExponentP(), rsaKey.getPrimeExponentQ(),
          rsaKey.getCrtCoefficient());
    } else {
      return new RSAKeyParameters(true, key.getModulus(), key.getPrivateExponent());
    }
  }

  // CHECKSTYLE:SKIP
  public static PSSSigner createPSSRSASigner(AlgorithmIdentifier sigAlgId)
      throws XiSecurityException {
    return createPSSRSASigner(sigAlgId, null);
  }

  // CHECKSTYLE:SKIP
  public static PSSSigner createPSSRSASigner(AlgorithmIdentifier sigAlgId,
      AsymmetricBlockCipher cipher) throws XiSecurityException {
    ParamUtil.requireNonNull("sigAlgId", sigAlgId);
    if (!PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigAlgId.getAlgorithm())) {
      throw new XiSecurityException("signature algorithm " + sigAlgId.getAlgorithm()
        + " is not allowed");
    }

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
    Digest mfgDig = getDigest(mfgDigAlgId);

    int saltSize = param.getSaltLength().intValue();
    int trailerField = param.getTrailerField().intValue();
    AsymmetricBlockCipher tmpCipher = (cipher == null) ? new RSABlindedEngine() : cipher;

    return new PSSSigner(tmpCipher, dig, mfgDig, saltSize, getTrailer(trailerField));
  }

  private static byte getTrailer(int trailerField) {
    if (trailerField == 1) {
      return org.bouncycastle.crypto.signers.PSSSigner.TRAILER_IMPLICIT;
    }

    throw new IllegalArgumentException("unknown trailer field");
  }

  // CHECKSTYLE:SKIP
  public static byte[] EMSA_PKCS1_v1_5_encoding(byte[] hashValue, int modulusBigLength,
      HashAlgoType hashAlgo) throws XiSecurityException {
    ParamUtil.requireNonNull("hashValue", hashValue);
    ParamUtil.requireNonNull("hashAlgo", hashAlgo);

    final int hashLen = hashAlgo.length();
    ParamUtil.requireRange("hashValue.length", hashValue.length, hashLen, hashLen);

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
  }

  // CHECKSTYLE:SKIP
  public static byte[] EMSA_PKCS1_v1_5_encoding(byte[] encodedDigestInfo, int modulusBigLength)
      throws XiSecurityException {
    ParamUtil.requireNonNull("encodedDigestInfo", encodedDigestInfo);

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
  }

  // CHECKSTYLE:SKIP
  public static byte[] EMSA_PSS_ENCODE(HashAlgoType contentDigest, byte[] hashValue,
      HashAlgoType mgfDigest, int saltLen, int modulusBitLength, SecureRandom random)
      throws XiSecurityException {
    final int hLen = contentDigest.length();
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

    byte[] dbMask = maskGeneratorFunction1(mgfDigest, hv, block.length - hLen - 1);
    for (int i = 0; i != dbMask.length; i++) {
      block[i] ^= dbMask[i];
    }

    block[0] &= (0xff >> ((block.length * 8) - emBits));

    System.arraycopy(hv, 0, block, block.length - hLen - 1, hLen);

    block[block.length - 1] = trailer;
    return block;
  }

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
  private static byte[] maskGeneratorFunction1(HashAlgoType mgfDigest,
      byte[] Z, // CHECKSTYLE:SKIP
      int length) {
    int mgfhLen = mgfDigest.length();
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
  }

  // CHECKSTYLE:SKIP
  public static byte[] dsaSigPlainToX962(byte[] signature) throws XiSecurityException {
    ParamUtil.requireNonNull("signature", signature);
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
  }

  // CHECKSTYLE:SKIP
  public static byte[] dsaSigX962ToPlain(byte[] x962Signature, int keyBitLen)
      throws XiSecurityException {
    ParamUtil.requireNonNull("x962Signature", x962Signature);
    ASN1Sequence seq = ASN1Sequence.getInstance(x962Signature);
    if (seq.size() != 2) {
      throw new IllegalArgumentException("invalid X962Signature");
    }
    BigInteger sigR = ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue();
    BigInteger sigS = ASN1Integer.getInstance(seq.getObjectAt(1)).getPositiveValue();
    return dsaSigToPlain(sigR, sigS, keyBitLen);
  }

  // CHECKSTYLE:SKIP
  public static byte[] dsaSigToPlain(BigInteger sigR, BigInteger sigS, int keyBitLen)
      throws XiSecurityException {
    ParamUtil.requireNonNull("sigR", sigR);
    ParamUtil.requireNonNull("sigS", sigS);

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
  }

  private static void bigIntToBytes(BigInteger num, byte[] dest, int destPos, int length) {
    byte[] bytes = num.toByteArray();
    if (bytes.length == length) {
      System.arraycopy(bytes, 0, dest, destPos, length);
    } else if (bytes.length < length) {
      System.arraycopy(bytes, 0, dest, destPos + length - bytes.length, bytes.length);
    } else {
      System.arraycopy(bytes, bytes.length - length, dest, destPos, length);
    }
  }

  private static Digest getDigest(AlgorithmIdentifier hashAlgo) throws XiSecurityException {
    HashAlgoType hat = HashAlgoType.getHashAlgoType(hashAlgo.getAlgorithm());
    if (hat != null) {
      return hat.createDigest();
    } else {
      throw new XiSecurityException(
          "could not get digest for " + hashAlgo.getAlgorithm().getId());
    }
  }

  public static byte[] getDigestPkcsPrefix(HashAlgoType hashAlgo) {
    byte[] bytes = digestPkcsPrefix.get(hashAlgo);
    return (bytes == null) ? null : Arrays.copyOf(bytes, bytes.length);
  }

}
