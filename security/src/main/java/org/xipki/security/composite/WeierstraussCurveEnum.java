// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.composite;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.xipki.security.OIDs;

import java.math.BigInteger;

/**
 * @author Lijun Liao (xipki)
 */
public enum WeierstraussCurveEnum {

  P256(OIDs.Curve.secp256r1),
  P384(OIDs.Curve.secp384r1),
  P521(OIDs.Curve.secp521r1),
  BP256(OIDs.Curve.brainpoolP256r1),
  BP384(OIDs.Curve.brainpoolP384r1);

  private final ECCurve curve;

  private final ECPoint base;

  private final ASN1ObjectIdentifier oid;

  WeierstraussCurveEnum(ASN1ObjectIdentifier oid) {
    X9ECParameters params = CustomNamedCurves.getByOID(oid);
    if (params == null) {
      params = ECNamedCurveTable.getByOID(oid);
    }

    this.oid = oid;
    this.curve = params.getCurve();
    this.base = params.getG();
  }

  public ASN1ObjectIdentifier oid() {
    return oid;
  }

  public BigInteger order() {
    return curve.getOrder();
  }

  public int fieldBitSize() {
    return curve.getFieldSize();
  }

  public int fieldByteSize() {
    return (curve.getFieldSize() + 7) / 8;
  }

  public ECPoint decodePoint(byte[] encoded) {
    return curve.decodePoint(encoded);
  }

  public ECPoint multiplyBase(BigInteger k) {
    return base.multiply(k).normalize();
  }

  public byte[] encodePoint(ECPoint point) {
    int fieldByteSize = (fieldBitSize() + 7) / 8;
    byte[] r = new byte[1 + 2 * fieldByteSize];
    r[0] = 4;
    BigIntegers.asUnsignedByteArray(point.getXCoord().toBigInteger(), r,
        1, fieldByteSize);
    BigIntegers.asUnsignedByteArray(point.getYCoord().toBigInteger(), r,
        1 + fieldByteSize, fieldByteSize);
    return r;
  }

}
