/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * EdDSA constants class.
 *
 * @author Lijun Liao
 */
// CHECKSTYLE:OFF
public class EdECConstants {

  private static final ASN1ObjectIdentifier id_edwards_curve_algs =
      new ASN1ObjectIdentifier("1.3.101");

  public static final ASN1ObjectIdentifier id_X25519 =
      id_edwards_curve_algs.branch("110").intern();
  public static final ASN1ObjectIdentifier id_X448 =
      id_edwards_curve_algs.branch("111").intern();
  public static final ASN1ObjectIdentifier id_ED25519 =
      id_edwards_curve_algs.branch("112").intern();
  public static final ASN1ObjectIdentifier id_ED448 =
      id_edwards_curve_algs.branch("113").intern();

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
    if (id_X25519.equals(curveOid)) {
      return 256;
    } else if (id_X448.equals(curveOid)) {
      return 448;
    } else if (id_ED25519.equals(curveOid)) {
      return 256;
    } else if (id_ED448.equals(curveOid)) {
      return 448;
    } else {
      return 0;
    }
  }

  public static int getPublicKeyByteSize(ASN1ObjectIdentifier curveOid) {
    if (id_X25519.equals(curveOid)) {
      return 32;
    } else if (id_X448.equals(curveOid)) {
      return 56;
    } else if (id_ED25519.equals(curveOid)) {
      return 32;
    } else if (id_ED448.equals(curveOid)) {
      return 57;
    } else {
      return 0;
    }
  }

  public static String getName(ASN1ObjectIdentifier curveOid) {
    if (id_X25519.equals(curveOid)) {
      return X25519;
    } else if (id_X448.equals(curveOid)) {
      return X448;
    } else if (id_ED25519.equals(curveOid)) {
      return ED25519;
    } else if (id_ED448.equals(curveOid)) {
      return ED448;
    } else {
      return null;
    }
  }

  public static ASN1ObjectIdentifier getCurveOid(String curveName) {
    curveName = curveName.toUpperCase();
    if (X25519.equals(curveName) || id_X25519.getId().equals(curveName)) {
      return id_X25519;
    } else if (X448.equals(curveName) || id_X448.getId().equals(curveName)) {
      return id_X448;
    } else if (ED25519.equals(curveName) || id_ED25519.getId().equals(curveName)) {
      return id_ED25519;
    } else if (ED448.equals(curveName) || id_ED448.getId().equals(curveName)) {
      return id_ED448;
    } else {
      return null;
    }
  }

}
