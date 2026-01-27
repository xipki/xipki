// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.crypt;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.OIDs;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * @author Lijun Liao (xipki)
 */
public enum MontgomeryCurveEnum {

  X25519(OIDs.x25519, "curve25519", 32, 32),
  X448(OIDs.x448, "curve448", 56, 56);

  private final int privateKeySize;

  private final int publicKeySize;

  private final byte[] encodedOid;

  private final String oid;

  private final String curveName;

  private final byte[] encodedCurveName;

  MontgomeryCurveEnum(ASN1ObjectIdentifier oid, String curveName,
                      int privateKeySize, int publicKeySize) {
    this.oid = oid.getId();
    this.curveName = curveName;
    this.privateKeySize = privateKeySize;
    this.publicKeySize = publicKeySize;
    try {
      this.encodedOid = oid.getEncoded();
      this.encodedCurveName = new DERPrintableString(curveName).getEncoded();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public String getCurveName() {
    return curveName;
  }

  public String getOid() {
    return oid;
  }

  public byte[] getEncodedOid() {
    return encodedOid.clone();
  }

  public int getPublicKeySize() {
    return publicKeySize;
  }

  public static MontgomeryCurveEnum ofEcParams(byte[] ecParams) {
    for (MontgomeryCurveEnum v : values()) {
      if (Arrays.equals(v.encodedOid, ecParams)
          || Arrays.equals(v.encodedCurveName, ecParams)) {
        return v;
      }
    }
    return null;
  }

  public static MontgomeryCurveEnum ofEcParamsNonNull(byte[] ecParams)
      throws HsmException {
    MontgomeryCurveEnum curve = ofEcParams(ecParams);
    if (curve == null) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "Unknown ecParams " + Hex.toHexString(ecParams));
    }
    return curve;
  }

  public byte[][] generateKeyPair(SecureRandom random) {
    byte[] sk = new byte[privateKeySize];
    byte[] pk = new byte[publicKeySize];
    if (this == X25519) {
      org.bouncycastle.math.ec.rfc7748.X25519.generatePrivateKey(random, sk);
      org.bouncycastle.math.ec.rfc7748.X25519.generatePublicKey(sk, 0, pk, 0);
    } else {
      org.bouncycastle.math.ec.rfc7748.X448.generatePrivateKey(random, sk);
      org.bouncycastle.math.ec.rfc7748.X448.generatePublicKey(sk, 0, pk, 0);
    }
    return new byte[][]{sk, pk};
  }

}
