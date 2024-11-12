// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.util.BigIntegers;
import org.xipki.util.Hex;

import java.math.BigInteger;
import java.security.spec.EllipticCurve;

/**
 * Chinese GM/SM Util class.
 * @author Lijun Liao (xipki)
 *
 */
public class GMUtil {

  private static final byte[] defaultIDA =
      new byte[]{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
          0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}; // the default value

  private static final byte[] sm2primev2A =
      Hex.decode("fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc");
  private static final byte[] sm2primev2B =
      Hex.decode("28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93");
  private static final byte[] sm2primev2Gx =
      Hex.decode("32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7");
  private static final byte[] sm2primev2Gy =
      Hex.decode("bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0");
  private static final int sm2primev2FieldSize = 32;

  private static final BigInteger bnSm2primev2B = new BigInteger(1, sm2primev2B);

  private GMUtil() {
  }

  public static byte[] getSM2Z(ASN1ObjectIdentifier curveOid, BigInteger pubPointX, BigInteger pubPointY) {
    return getSM2Z(defaultIDA, curveOid, pubPointX, pubPointY);
  }

  public static byte[] getDefaultIDA() {
    return defaultIDA.clone();
  }

  public static byte[] getSM2Z(
      byte[] userID, ASN1ObjectIdentifier curveOid, BigInteger pubPointX, BigInteger pubPointY) {
    SM3Digest digest = new SM3Digest();

    addUserId(digest, userID == null ? defaultIDA : userID);

    int fieldSize;
    if (GMObjectIdentifiers.sm2p256v1.equals(curveOid)) {
      fieldSize = sm2primev2FieldSize;
      digest.update(sm2primev2A,  0, fieldSize);
      digest.update(sm2primev2B,  0, fieldSize);
      digest.update(sm2primev2Gx, 0, fieldSize);
      digest.update(sm2primev2Gy, 0, fieldSize);
    } else {
      X9ECParameters ecParams = GMNamedCurves.getByOID(curveOid);
      fieldSize = (ecParams.getCurve().getFieldSize() + 7) / 8;
      addFieldElement(digest, ecParams.getCurve().getA());
      addFieldElement(digest, ecParams.getCurve().getB());
      addFieldElement(digest, ecParams.getG().getAffineXCoord());
      addFieldElement(digest, ecParams.getG().getAffineYCoord());
    }

    digest.update(BigIntegers.asUnsignedByteArray(fieldSize, pubPointX), 0, fieldSize);
    digest.update(BigIntegers.asUnsignedByteArray(fieldSize, pubPointY), 0, fieldSize);

    byte[] result = new byte[digest.getDigestSize()];
    digest.doFinal(result, 0);
    return result;
  } // method getSM2Z

  private static void addUserId(Digest digest, byte[] userId) {
    int len = userId.length * 8;
    if (len > 0xFFFF) {
      throw new IllegalArgumentException("userId too long");
    }

    digest.update((byte)(len >> 8 & 0xFF));
    digest.update((byte)(len & 0xFF));
    digest.update(userId, 0, userId.length);
  }

  private static void addFieldElement(Digest digest, ECFieldElement element) {
    byte[] encoded = element.getEncoded();
    digest.update(encoded, 0, encoded.length);
  }

  public static boolean isSm2primev2Curve(EllipticCurve curve) {
    return curve.getB().equals(bnSm2primev2B);
  }

  public static boolean isSm2primev2Curve(ECCurve curve) {
    return curve.getB().toBigInteger().equals(bnSm2primev2B);
  }

}
