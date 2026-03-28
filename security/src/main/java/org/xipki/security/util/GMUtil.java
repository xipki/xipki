// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.xipki.security.HashAlgo;
import org.xipki.util.codec.Hex;
import org.xipki.util.codec.asn1.Asn1Util;
import org.xipki.util.io.IoUtil;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Arrays;

/**
 * GMUtil.
 *
 * @author Lijun Liao (xipki)
 */
public class GMUtil {

  private static final BigInteger bnSm2primev1Order = new BigInteger(
      "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123",  16);

  private static final byte[] sm2CurveData = Hex.decode(
      "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc" + // A
      "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93" + // B
      "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7" + // Gx
      "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"); // Gy

  private static final byte[] sm2DefaultIDA =
      new byte[]{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
          0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

  public static byte[] getSM2Z(byte[] userID, byte[] pubPoint) {
    MessageDigest digest = HashAlgo.SM3.createDigest();

    if (userID == null) {
      digest.update((byte) 0x00);
      digest.update((byte) 0x80);
      digest.update(sm2DefaultIDA, 0, sm2DefaultIDA.length);
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

    return digest.digest();
  } // method getSM2Z

  public static byte[] getSM2Z(byte[] userID, BigInteger pubPointX, BigInteger pubPointY) {
    byte[] ecPoint = IoUtil.concatenate(new byte[] {4},
        BigIntegers.asUnsignedByteArray(32, pubPointX),
        BigIntegers.asUnsignedByteArray(32, pubPointY));
    return getSM2Z(userID, ecPoint);
  } // method getSM2Z

  public static boolean isSm2primev1Curve(BigInteger curveOrder) {
    return bnSm2primev1Order.equals(curveOrder);
  }

  public static byte[] signRawSm2(BigInteger sk, byte[] ehash, SecureRandom random) {
    return signEhash(sk, ehash, random);
  }

  public static byte[] signSm2Sm3WithZa(
      BigInteger sk, byte[] za, byte[] data, SecureRandom random) {
    byte[] ehash = HashAlgo.SM3.hash(za, data);
    return signEhash(sk, ehash, random);
  }

  public static byte[] signSm2Sm3(
      BigInteger sk, byte[] userID, BigInteger pubPointX, BigInteger pubPointY,
      byte[] data, SecureRandom random) {
    byte[] za = KeyUtil.getSM2Z(userID, pubPointX, pubPointY);
    byte[] ehash = HashAlgo.SM3.hash(za, data);
    return signEhash(sk, ehash, random);
  }

  public static boolean verifyRawSm2(ECPoint publicPoint, byte[] ehash, byte[] signature)
      throws SignatureException {
    return verifyEhash(publicPoint, ehash, signature);
  }

  public static boolean verifySm2Sm3(ECPoint publicPoint, byte[] userID, byte[] data,
                                    byte[] signature) throws SignatureException {
    byte[] za = KeyUtil.getSM2Z(userID, publicPoint.getXCoord().toBigInteger(),
                  publicPoint.getYCoord().toBigInteger());
    byte[] ehash = HashAlgo.SM3.hash(za, data);
    return verifyEhash(publicPoint, ehash, signature);
  }

  private static byte[] signEhash(BigInteger sk, byte[] hash, SecureRandom random) {
    WeierstraussCurveEnum SM2 = WeierstraussCurveEnum.SM2;
    BigInteger order = SM2.getOrder();
    BigInteger eh= new BigInteger(1, hash);

    BigInteger r;
    BigInteger s;

    while (true) {
      BigInteger k = new BigInteger(order.bitLength(), random);
      k = k.mod(order);

      // (x, y) = k * G
      ECPoint kG = SM2.multiplyBase(k);
      BigInteger x = kG.getXCoord().toBigInteger();

      // r = e + x
      r = eh.add(x).mod(order);
      if (r.signum() == 0) {
        continue;
      }

      // s = (1 + d)^-1 * (k -r * d)
      BigInteger inv = sk.add(BigInteger.ONE).modInverse(order);
      BigInteger rd  = r.multiply(sk).mod(order);
      BigInteger k_minus_rd = k.subtract(rd).mod(order);
      if (k_minus_rd.signum() == -1) {
        k_minus_rd = order.add(k_minus_rd);
      }

      s = inv.multiply(k_minus_rd).mod(order);
      if (s.signum() != 0) {
        break;
      }
    }

    byte[] sig = new byte[64];
    BigIntegers.asUnsignedByteArray(r, sig, 0, 32);
    BigIntegers.asUnsignedByteArray(s, sig, 32, 32);
    return Asn1Util.dsaSigPlainToX962(sig);
  }

  private static boolean verifyEhash(ECPoint publicPoint, byte[] ehash, byte[] signature)
      throws SignatureException {
    signature = Asn1Util.dsaSigX962ToPlain(signature, 32);
    if (signature.length != 64) {
      throw new SignatureException("raw signature's length != 64: " + signature.length);
    }

    // verify ehash
    BigInteger e = new BigInteger(1, ehash);
    BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature,  0, 32));
    BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, 32, 64));

    WeierstraussCurveEnum curve = WeierstraussCurveEnum.SM2;
    BigInteger order = curve.getOrder();

    // 1. t = r + s mod n
    BigInteger t = r.add(s).mod(order);

    // 2. (x,y) = s*G + t*Q
    ECPoint xy = curve.multiplyBase(s).add(publicPoint.multiply(t)).normalize();
    BigInteger x = xy.getXCoord().toBigInteger();

    // 3. r2 = e + x
    BigInteger r2 = e.add(x);

    // 4. valid if r2 - r = 0 mod n
    BigInteger delta = r2.subtract(r).mod(order);
    return delta.equals(BigInteger.ZERO);
  }

}
