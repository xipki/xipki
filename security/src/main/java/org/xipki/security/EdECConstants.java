// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * EdDSA constants class.
 *
 * @author Lijun Liao (xipki)
 */
public class EdECConstants {

  private static final ASN1ObjectIdentifier id_edwards_curve_algs = new ASN1ObjectIdentifier("1.3.101");
  public static final ASN1ObjectIdentifier id_X25519 = id_edwards_curve_algs.branch("110");
  public static final ASN1ObjectIdentifier id_X448 = id_edwards_curve_algs.branch("111");
  public static final ASN1ObjectIdentifier id_ED25519 = id_edwards_curve_algs.branch("112");
  public static final ASN1ObjectIdentifier id_ED448 = id_edwards_curve_algs.branch("113");

  public static final String X25519 = "X25519";

  public static final String ED25519 = "ED25519";

  public static final String X448 = "X448";

  public static final String ED448 = "ED448";

  private EdECConstants() {
  }

  public static boolean isEdwardsCurve(ASN1ObjectIdentifier curveOid) {
    return id_ED25519.equals(curveOid) || id_ED448.equals(curveOid);
  }

  public static boolean isMontgomeryCurve(ASN1ObjectIdentifier curveOid) {
    return id_X25519.equals(curveOid) || id_X448.equals(curveOid);
  }

  public static boolean isEdwardsOrMontgomeryCurve(ASN1ObjectIdentifier curveOid) {
    return isEdwardsCurve(curveOid) || isMontgomeryCurve(curveOid);
  }

  public static int getKeyBitSize(ASN1ObjectIdentifier curveOid) {
    return id_X25519.equals(curveOid) ? 256
        : id_X448.equals(curveOid) ? 448
        : id_ED25519.equals(curveOid) ? 256
        : id_ED448.equals(curveOid) ? 448 : 0;
  }

  public static int getPublicKeyByteSize(ASN1ObjectIdentifier curveOid) {
    return id_X25519.equals(curveOid) ? 32
        : id_X448.equals(curveOid) ? 56
        : id_ED25519.equals(curveOid) ? 32
        : id_ED448.equals(curveOid) ? 57 : 0;
  }

  public static String getName(ASN1ObjectIdentifier curveOid) {
    return id_X25519.equals(curveOid) ? X25519
        : id_X448.equals(curveOid) ? X448
        : id_ED25519.equals(curveOid) ? ED25519
        : id_ED448.equals(curveOid) ? ED448 : null;
  }

  public static ASN1ObjectIdentifier getCurveOid(String curveName) {
    curveName = curveName.toUpperCase();
    return (X25519.equals(curveName) ||  id_X25519.getId().equals(curveName)) ? id_X25519
        :    (X448.equals(curveName) ||    id_X448.getId().equals(curveName)) ? id_X448
        : (ED25519.equals(curveName) || id_ED25519.getId().equals(curveName)) ? id_ED25519
        :   (ED448.equals(curveName) ||   id_ED448.getId().equals(curveName)) ? id_ED448 : null;
  }

}
