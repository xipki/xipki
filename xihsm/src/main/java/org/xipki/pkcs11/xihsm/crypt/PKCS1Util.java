// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.crypt;

import org.bouncycastle.util.encoders.Hex;
import org.xipki.util.codec.Args;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 * PKCS#1 utility class.
 *
 * @author Lijun Liao (xipki)
 */
public class PKCS1Util {

  private static final Map<HashAlgo, byte[]> digestPkcsPrefix =
    new HashMap<>();

  static {
    addDigestPkcsPrefix(HashAlgo.SHA1,
      "3021300906052b0e03021a05000414");
    addDigestPkcsPrefix(HashAlgo.SHA224,
      "302d300d06096086480165030402040500041c");
    addDigestPkcsPrefix(HashAlgo.SHA256,
      "3031300d060960864801650304020105000420");
    addDigestPkcsPrefix(HashAlgo.SHA384,
      "3041300d060960864801650304020205000430");
    addDigestPkcsPrefix(HashAlgo.SHA512,
      "3051300d060960864801650304020305000440");
  } // method static

  private static void addDigestPkcsPrefix(HashAlgo algo, String prefix) {
    digestPkcsPrefix.put(algo, Hex.decode(prefix));
  }

  public static byte[] EMSA_PKCS1_v1_5_encode(
    byte[] hashValue, int modulusBitLength, HashAlgo hashAlgo)
    throws Exception {
    final int hashLen = Args.notNull(hashAlgo, "hashAlgo").getLength();
    Args.range(Args.notNull(hashValue, "hashValue").length,
      "hashValue.length", hashLen, hashLen);

    int blockSize = (modulusBitLength + 7) / 8;
    byte[] prefix = digestPkcsPrefix.get(hashAlgo);

    if (prefix.length + hashLen + 3 > blockSize) {
      throw new Exception("data too long (maximal " + (blockSize - 3)
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

  public static byte[] EMSA_PKCS1_v1_5_encode(
    byte[] encodedDigestInfo, int modulusBitLength)
      throws Exception {
    int msgLen = Args.notNull(encodedDigestInfo, "encodedDigestInfo").length;
    int blockSize = (modulusBitLength + 7) / 8;

    if (msgLen + 3 > blockSize) {
      throw new Exception("data too long (maximal " + (blockSize - 3)
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

    System.arraycopy(encodedDigestInfo, 0, block, offset,
        encodedDigestInfo.length);
    return block;
  } // method EMSA_PKCS1_v1_5_encoding

  public static byte[] EMSA_PSS_ENCODE(
    HashAlgo contentDigest, byte[] hashValue, HashAlgo mgfDigest,
    int saltLen, int modulusBitLength, SecureRandom random)
    throws Exception {
    final int hLen = contentDigest.getLength();
    final byte[] salt = new byte[saltLen];
    final byte[] mDash = new byte[8 + saltLen + hLen];
    final byte trailer = (byte) 0xBC;

    if (hashValue.length != hLen) {
      throw new Exception("hashValue.length is incorrect: "
        + hashValue.length + " != " + hLen);
    }

    int emBits = modulusBitLength - 1;
    if (emBits < (8 * hLen + 8 * saltLen + 9)) {
      throw new IllegalArgumentException(
          "key too small for specified hash and salt lengths");
    }

    System.arraycopy(hashValue, 0, mDash,
        mDash.length - hLen - saltLen, hLen);

    random.nextBytes(salt);
    System.arraycopy(salt, 0, mDash,
        mDash.length - saltLen, saltLen);

    byte[] hv = contentDigest.hash(mDash);
    byte[] block = new byte[(emBits + 7) / 8];
    block[block.length - saltLen - 1 - hLen - 1] = 0x01;
    System.arraycopy(salt, 0, block,
        block.length - saltLen - hLen - 1, saltLen);

    int dbMaskLen = block.length - hLen - 1;
    byte[] dbMask = mgf(mgfDigest, hv, dbMaskLen);

    for (int i = 0; i != dbMaskLen; i++) {
      block[i] ^= dbMask[i];
    }

    block[0] &= (byte) (0xff >> ((block.length * 8) - emBits));

    System.arraycopy(hv, 0, block, block.length - hLen - 1, hLen);

    block[block.length - 1] = trailer;
    return block;
  } // method EMSA_PSS_ENCODE

  /**
   * mask generator function, as described in PKCS1v2.
   */
  private static byte[] mgf(HashAlgo mgfDigest, byte[] Z, int length) {
    return mgf1(mgfDigest, Z, length);
  }

  private static byte[] mgf1(HashAlgo mgfDigest, byte[] Z, int length) {
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
  } // method mgf1

  /**
   * int to octet string.
   */
  private static void ItoOSP(int i, byte[] sp, int spOffset) {
    sp[spOffset  ] = (byte)(i >>> 24);
    sp[spOffset + 1] = (byte)(i >>> 16);
    sp[spOffset + 2] = (byte)(i >>> 8);
    sp[spOffset + 3] = (byte)(i);
  }

}
