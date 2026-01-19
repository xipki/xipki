// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.crypt;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.OIDs;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * @author Lijun Liao (xipki)
 */
public enum WeierstraussCurveEnum {

  P256(OIDs.secp256r1),
  P384(OIDs.secp384r1),
  P521(OIDs.secp521r1),
  BP256(OIDs.brainpoolP256r1),
  BP384(OIDs.brainpoolP384r1),
  BP512(OIDs.brainpoolP512r1),
  SM2(OIDs.sm2p256v1),
  FRP256V1(OIDs.frp256v1);

  private final ECCurve curve;

  private final ECPoint base;

  private final byte[] encodedOid;

  private final String oid;

  WeierstraussCurveEnum(ASN1ObjectIdentifier oid) {
    X9ECParameters params = CustomNamedCurves.getByOID(oid);
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
      throws HsmException {
    WeierstraussCurveEnum curve = ofEcParams(ecParams);
    if (curve == null) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "Unknown ecParams " + Hex.toHexString(ecParams));
    }
    return curve;
  }

  public ECPoint decodePoint(byte[] encoded) throws HsmException {
    try {
      return curve.decodePoint(encoded);
    } catch (RuntimeException e) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "invalid encoded EC point", e);
    }
  }

  public ECPoint multiplyBase(BigInteger k) {
    return base.multiply(k).normalize();
  }

  public byte[] encodePoint(ECPoint point) {
    int fieldByteSize = (getFieldBitSize() + 7) / 8;
    byte[] r = new byte[1 + 2 * fieldByteSize];
    r[0] = 4;
    BigIntegers.asUnsignedByteArray(point.getXCoord().toBigInteger(), r,
        1, fieldByteSize);
    BigIntegers.asUnsignedByteArray(point.getYCoord().toBigInteger(), r,
        1 + fieldByteSize, fieldByteSize);
    return r;
  }

  public byte[][] generateKeyPair(SecureRandom random) {
    BigInteger order = getOrder();
    int fieldByteSize = (getFieldBitSize() + 7) / 8;

    BigInteger sk;
    while (true) {
      byte[] bytes = new byte[fieldByteSize];
      random.nextBytes(bytes);

      sk = new BigInteger(1, bytes).mod(order);
      if (sk.signum() != 0) {
        break;
      }
    }

    ECPoint pk = multiplyBase(sk);
    return new byte[][] {BigIntegers.asUnsignedByteArray(fieldByteSize, sk),
        encodePoint(pk)};
  }

}
