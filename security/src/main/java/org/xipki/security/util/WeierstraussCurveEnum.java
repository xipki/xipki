// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.OIDs;
import org.xipki.security.exception.XiSecurityException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Weierstrauss Curve Enum enumeration.
 *
 * @author Lijun Liao (xipki)
 */
public enum WeierstraussCurveEnum {

  P256 (OIDs.Curve.secp256r1),
  P384 (OIDs.Curve.secp384r1),
  P521 (OIDs.Curve.secp521r1),
  BP256(OIDs.Curve.brainpoolP256r1),
  BP384(OIDs.Curve.brainpoolP384r1),
  BP512(OIDs.Curve.brainpoolP512r1),
  SM2  (OIDs.Curve.sm2p256v1),
  FRP256V1(OIDs.Curve.frp256v1);

  private final ECCurve curve;

  private final ECPoint base;

  private final byte[] encodedOid;

  private final String oid;

  WeierstraussCurveEnum(ASN1ObjectIdentifier oid) {
    X9ECParameters params = ECNamedCurveTable.getByOID(oid);
    if (params == null) {
      params = ECNamedCurveTable.getByOID(oid);
    }

    this.oid = oid.getId();
    this.curve = params.getCurve();
    this.base = params.getG();
    try {
      this.encodedOid = oid.getEncoded();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public String getOid() {
    return oid;
  }

  public BigInteger getOrder() {
    return curve.getOrder();
  }

  public int getFieldBitSize() {
    return curve.getFieldSize();
  }

  public int getFieldByteSize() {
    return (curve.getFieldSize() + 7) / 8;
  }

  public byte[] getEncodedOid() {
    return encodedOid.clone();
  }

  public static WeierstraussCurveEnum ofEcParams(byte[] ecParams) {
    for (WeierstraussCurveEnum v : values()) {
      if (Arrays.equals(v.encodedOid, ecParams)) {
        return v;
      }
    }
    return null;
  }

  public static WeierstraussCurveEnum ofEcParamsNonNull(byte[] ecParams)
      throws XiSecurityException {
    WeierstraussCurveEnum curve = ofEcParams(ecParams);
    if (curve == null) {
      throw new XiSecurityException("Unknown ecParams " + Hex.toHexString(ecParams));
    }
    return curve;
  }

  public ECPoint decodePoint(byte[] encoded) throws XiSecurityException {
    try {
      return curve.decodePoint(encoded);
    } catch (RuntimeException e) {
      throw new XiSecurityException("invalid encoded EC point", e);
    }
  }

  public ECPoint multiplyBase(BigInteger k) {
    return base.multiply(k).normalize();
  }

  public byte[] encodePoint(ECPoint point) {
    int fieldByteSize = (getFieldBitSize() + 7) / 8;
    byte[] r = new byte[1 + 2 * fieldByteSize];
    r[0] = 4;
    BigIntegers.asUnsignedByteArray(point.getXCoord().toBigInteger(), r, 1, fieldByteSize);
    BigIntegers.asUnsignedByteArray(point.getYCoord().toBigInteger(), r, 1 + fieldByteSize,
        fieldByteSize);
    return r;
  }

  /**
   * Returns a uniformly distributed random scalar in [1, order - 1], by rejection sampling
   * (FIPS 186-5, A.2.2). Reducing a random value of the field size modulo the order would be
   * biased, e.g. for P-521 (528 random bits modulo a 521-bit order).
   *
   * @param random the source of randomness.
   * @return the random scalar.
   */
  public BigInteger randomScalar(SecureRandom random) {
    BigInteger order = getOrder();
    int bitLength = order.bitLength();
    while (true) {
      BigInteger k = new BigInteger(bitLength, random);
      if (k.signum() != 0 && k.compareTo(order) < 0) {
        return k;
      }
    }
  }

  public byte[][] generateKeyPair(SecureRandom random) {
    int fieldByteSize = (getFieldBitSize() + 7) / 8;
    BigInteger sk = randomScalar(random);
    ECPoint pk = multiplyBase(sk);
    return new byte[][] {BigIntegers.asUnsignedByteArray(fieldByteSize, sk), encodePoint(pk)};
  }

}
