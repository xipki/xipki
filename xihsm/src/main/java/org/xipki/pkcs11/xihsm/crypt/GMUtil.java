// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.crypt;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.encoders.Hex;

/**
 * Chinese GM/SM Util class.
 * @author Lijun Liao (xipki)
 *
 */
public class GMUtil {

  private static final byte[] defaultIDA =
      new byte[]{
          0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
          0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}; // the default value

  private static final byte[] encoded_defaultIDA;

  static {
    encoded_defaultIDA = new byte[2 + defaultIDA.length];
    encoded_defaultIDA[1] = (byte) 0x80;
    System.arraycopy(defaultIDA, 0, encoded_defaultIDA, 2, defaultIDA.length);
  }

  private static final byte[] sm2CurveData = Hex.decode(
      "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc" + // A
      "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93" + // B
      "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7" + // Gx
      "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"); // Gy

  private GMUtil() {
  }

  public static byte[] getSM2Z(byte[] pubPoint) {
    return getSM2Z(defaultIDA, pubPoint);
  }

  public static byte[] getSM2Z(byte[] userID, byte[] pubPoint) {
    SM3Digest digest = new SM3Digest();

    if (userID == null) {
      digest.update(encoded_defaultIDA, 0, encoded_defaultIDA.length);
    } else {
      if (userID.length > 0x1FFF) {
        throw new IllegalArgumentException("userId too long");
      }

      int len = userID.length * 8;
      digest.update((byte)(len >> 8));
      digest.update((byte)(len & 0xFF));
      digest.update(userID, 0, userID.length);
    }

    digest.update(sm2CurveData, 0, sm2CurveData.length);
    digest.update(pubPoint, 1, 64);

    byte[] result = new byte[digest.getDigestSize()];
    digest.doFinal(result, 0);
    return result;
  } // method getSM2Z

}
