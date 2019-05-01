/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

// CHECKSTYLE:OFF
public class EdECConstants {

  public static final String ALG_X25519 = "X25519";

  public static final String ALG_Ed25519 = "Ed25519";

  public static final String ALG_X448 = "X448";

  public static final String ALG_Ed448 = "Ed448";

  public static final String curve25519 = "curve25519";

  public static final String edwards25519 = "edwards25519";

  public static final String curve448 = "curve448";

  public static final String edwards448 = "edwards448";

  private EdECConstants() {
  }

  public static boolean isEdwardsCurve(String curveName) {
    return edwards25519.equalsIgnoreCase(curveName) || edwards448.equalsIgnoreCase(curveName);
  }

  public static boolean isMontgemoryCurve(String curveName) {
    return curve25519.equalsIgnoreCase(curveName) || curve448.equalsIgnoreCase(curveName);
  }

  public static boolean isEdwardsOrMontgemoryCurve(String curveName) {
    return isEdwardsCurve(curveName) || isMontgemoryCurve(curveName);
  }

  public static int getKeyBitSizeForCurve(String curveName) {
    if (curve25519.equalsIgnoreCase(curveName)) {
      return 256;
    } else if (curve448.equalsIgnoreCase(curveName)) {
      return 448;
    } else if (edwards25519.equalsIgnoreCase(curveName)) {
      return 256;
    } else if (edwards448.equalsIgnoreCase(curveName)) {
      return 448;
    } else {
      throw new IllegalArgumentException("unknown curveName " + curveName);
    }
  }

  public static int getKeyBitSizeForKeyAlgName(String keyAlgName) {
    if (ALG_X25519.equalsIgnoreCase(keyAlgName)) {
      return 256;
    } else if (ALG_X448.equalsIgnoreCase(keyAlgName)) {
      return 448;
    } else if (ALG_Ed25519.equalsIgnoreCase(keyAlgName)) {
      return 256;
    } else if (ALG_Ed448.equalsIgnoreCase(keyAlgName)) {
      return 448;
    } else {
      throw new IllegalArgumentException("unknown keyAlgName " + keyAlgName);
    }
  }

  public static String getCurveForKeyAlg(String keyAlg) {
    if (ALG_X25519.equalsIgnoreCase(keyAlg)) {
      return curve25519;
    } else if (ALG_X448.equalsIgnoreCase(keyAlg)) {
      return curve448;
    } else if (ALG_Ed25519.equalsIgnoreCase(keyAlg)) {
      return edwards25519;
    } else if (ALG_Ed448.equalsIgnoreCase(keyAlg)) {
      return edwards448;
    } else {
      return null;
    }
  }

  public static String getCurveForKeyAlg(AlgorithmIdentifier algId) {
    ASN1ObjectIdentifier oid = algId.getAlgorithm();
    if (EdECObjectIdentifiers.id_X25519.equals(oid)) {
      return curve25519;
    } else if (EdECObjectIdentifiers.id_X448.equals(oid)) {
      return curve448;
    } else if (EdECObjectIdentifiers.id_Ed25519.equals(oid)) {
      return edwards25519;
    } else if (EdECObjectIdentifiers.id_Ed448.equals(oid)) {
      return edwards448;
    } else {
      return null;
    }
  }

  public static String getKeyAlgNameForKeyAlg(AlgorithmIdentifier algId) {
    ASN1ObjectIdentifier oid = algId.getAlgorithm();
    if (oid.equals(EdECObjectIdentifiers.id_Ed25519)) {
      return ALG_Ed25519;
    } else if (oid.equals(EdECObjectIdentifiers.id_Ed448)) {
      return ALG_Ed448;
    } else if (oid.equals(EdECObjectIdentifiers.id_X25519)) {
      return ALG_X25519;
    } else if (oid.equals(EdECObjectIdentifiers.id_X448)) {
      return ALG_X448;
    } else {
      return null;
    }
  }

  public static String getKeyAlgNameForCurve(String curveName) {
    if (curve25519.equalsIgnoreCase(curveName)) {
      return ALG_X25519;
    } else if (curve448.equalsIgnoreCase(curveName)) {
      return ALG_X448;
    } else if (edwards25519.equalsIgnoreCase(curveName)) {
      return ALG_Ed25519;
    } else if (edwards448.equalsIgnoreCase(curveName)) {
      return ALG_Ed448;
    } else {
      return null;
    }
  }

  public static ASN1ObjectIdentifier getKeyAlgIdForCurve(String curveName) {
    if (curve25519.equalsIgnoreCase(curveName)) {
      return EdECObjectIdentifiers.id_X25519;
    } else if (curve448.equalsIgnoreCase(curveName)) {
      return EdECObjectIdentifiers.id_X448;
    } else if (edwards25519.equalsIgnoreCase(curveName)) {
      return EdECObjectIdentifiers.id_Ed25519;
    } else if (edwards448.equalsIgnoreCase(curveName)) {
      return EdECObjectIdentifiers.id_Ed448;
    } else {
      return null;
    }
  }

  public static ASN1ObjectIdentifier getKeyAlgIdForKeyAlgName(String algName) {
    if (ALG_X25519.equalsIgnoreCase(algName)) {
      return EdECObjectIdentifiers.id_X25519;
    } else if (ALG_X448.equalsIgnoreCase(algName)) {
      return EdECObjectIdentifiers.id_X448;
    } else if (ALG_Ed25519.equalsIgnoreCase(algName)) {
      return EdECObjectIdentifiers.id_Ed25519;
    } else if (ALG_Ed448.equalsIgnoreCase(algName)) {
      return EdECObjectIdentifiers.id_Ed448;
    } else {
      return null;
    }
  }

}
