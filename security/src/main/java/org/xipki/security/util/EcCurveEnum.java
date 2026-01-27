// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.xipki.security.OIDs;
import org.xipki.util.codec.Hex;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * @author Lijun Liao (xipki)
 */
public enum EcCurveEnum {

  // EC
  SECP256R1(OIDs.Curve.secp256r1, 256, "P-256", "SECP256R1"),
  SECP384R1(OIDs.Curve.secp384r1, 384, "P-384", "SECP384R1"),
  SECP521R1(OIDs.Curve.secp521r1, 521, "P-521", "SECP521R1"),
  /**
   * BrainPool P256R1 EC Key
   */
  BRAINPOOLP256R1(OIDs.Curve.brainpoolP256r1, 256, "BRAINPOOLP256R1"),
  /**
   * BrainPool P384R1 EC Key
   */
  BRAINPOOLP384R1(OIDs.Curve.brainpoolP384r1, 384, "BRAINPOOLP384R1"),
  /**
   * BrainPool P512R1 EC Key
   */
  BRAINPOOLP512R1(OIDs.Curve.brainpoolP512r1, 512, "BRAINPOOLP512R1"),
  SM2P256V1(OIDs.Curve.sm2p256v1, 256, "SM2P256V1"),
  FRP256V1( OIDs.Curve.frp256v1,  256, "FRP256V1"),
  ED25519(false, OIDs.Curve.id_ED25519, 256, "ED25519"),
  ED448(false,   OIDs.Curve.id_ED448,   448, "ED448"),
  X25519(false,  OIDs.Curve.id_X25519,  256, "X25519"),
  X448(false,    OIDs.Curve.id_X448,    448, "X448");

  private final int fieldByteSize;

  private final int fieldBitSize;

  private final List<String> aliases;

  private final ASN1ObjectIdentifier oid;

  private final AlgorithmIdentifier algId;

  private final byte[] encodedOid;

  EcCurveEnum(ASN1ObjectIdentifier oid, int fieldBitSize, String... aliases) {
    this(true, oid, fieldBitSize, aliases);
  }

  EcCurveEnum(boolean weierstrauss, ASN1ObjectIdentifier oid,
              int fieldBitSize, String... aliases) {
    this.oid = oid;
    this.fieldBitSize = fieldBitSize;
    this.fieldByteSize = (fieldBitSize + 7) / 8;
    this.aliases = new ArrayList<>(1);
    this.aliases.addAll(Arrays.asList(aliases));
    this.aliases.add(oid.getId());

    if (weierstrauss) {
      this.algId = new AlgorithmIdentifier(OIDs.Algo.id_ecPublicKey, oid);
    } else {
      this.algId = new AlgorithmIdentifier(oid);
    }

    try {
      this.encodedOid = oid.getEncoded();
    } catch (IOException e) {
      throw new RuntimeException("shall not happen", e);
    }
  }

  public ASN1ObjectIdentifier getOid() {
    return oid;
  }

  public String getMainAlias() {
    return aliases.get(0);
  }

  public byte[] getEncodedOid() {
    return encodedOid.clone();
  }

  public int getFieldBitSize() {
    return fieldBitSize;
  }

  public int getFieldByteSize() {
    return fieldByteSize;
  }

  public AlgorithmIdentifier getAlgId() {
    return algId;
  }

  public static EcCurveEnum ofOid(ASN1ObjectIdentifier oid) {
    for (EcCurveEnum m : EcCurveEnum.values()) {
      if (m.oid.equals(oid)) {
        return m;
      }
    }
    return null;
  }

  public static EcCurveEnum ofAlias(String alias) {
    alias = alias.toUpperCase(Locale.US);
    for (EcCurveEnum m : EcCurveEnum.values()) {
      if (m.aliases.contains(alias)) {
        return m;
      }
    }
    return null;
  }

  public static EcCurveEnum ofEncodedOid(byte[] encodedOid) {
    for (EcCurveEnum m : EcCurveEnum.values()) {
      if (Arrays.equals(m.encodedOid, encodedOid)) {
        return m;
      }
    }

    throw new IllegalArgumentException(
        "found no EcCurveEnum for OID " + Hex.encode(encodedOid));
  }

}
