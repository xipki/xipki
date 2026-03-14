// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.crypt;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.security.OIDs;

import java.io.IOException;
import java.util.Arrays;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public enum EdwardsCurveEnum {

  ED25519(OIDs.Curve.id_ED25519, "edwards25519", 32, 32, 64),
  ED448(OIDs.Curve.id_ED448, "edwards448", 57, 57, 114);

  private final int privateKeySize;

  private final int publicKeySize;

  private final int signatureSize;

  private final byte[] encodedOid;

  private final String oid;

  private final String curveName;

  private final byte[] encodedCurveName;

  EdwardsCurveEnum(ASN1ObjectIdentifier oid, String curveName,
                  int privateKeySize, int publicKeySize, int signatureSize) {
    this.oid = oid.getId();
    this.curveName = curveName;
    this.privateKeySize = privateKeySize;
    this.publicKeySize = publicKeySize;
    this.signatureSize = signatureSize;
    try {
      this.encodedOid = oid.getEncoded();
      this.encodedCurveName = new DERPrintableString(curveName).getEncoded();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
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

  public int getSignatureSize() {
    return signatureSize;
  }

  public String getCurveName() {
    return curveName;
  }

  public static EdwardsCurveEnum ofEcParams(byte[] ecParams) {
    for (EdwardsCurveEnum v : values()) {
      if (Arrays.equals(v.encodedOid, ecParams) || Arrays.equals(v.encodedCurveName, ecParams)) {
        return v;
      }
    }
    return null;
  }

  public static EdwardsCurveEnum ofEcParamsNonNull(byte[] ecParams) throws HsmException {
    EdwardsCurveEnum curve = ofEcParams(ecParams);
    if (curve == null) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "Unknown ecParams " + Hex.toHexString(ecParams));
    }
    return curve;
  }

}
