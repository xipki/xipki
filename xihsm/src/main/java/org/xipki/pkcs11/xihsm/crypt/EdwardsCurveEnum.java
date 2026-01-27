// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.crypt;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.math.ec.rfc8032.Ed448;
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
public enum EdwardsCurveEnum {

  ED25519(OIDs.ed25519, "edwards25519", 32, 32, 64),
  ED448(OIDs.ed448, "edwards448", 57, 57, 114);

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
      if (Arrays.equals(v.encodedOid, ecParams)
          || Arrays.equals(v.encodedCurveName, ecParams)) {
        return v;
      }
    }
    return null;
  }

  public static EdwardsCurveEnum ofEcParamsNonNull(byte[] ecParams)
      throws HsmException {
    EdwardsCurveEnum curve = ofEcParams(ecParams);
    if (curve == null) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "Unknown ecParams " + Hex.toHexString(ecParams));
    }
    return curve;
  }

  public byte[][] generateKeyPair(SecureRandom random) {
    byte[] sk = new byte[privateKeySize];
    byte[] pk = new byte[publicKeySize];
    if (this == ED25519) {
      Ed25519.generatePrivateKey(random, sk);
      Ed25519.generatePublicKey(sk, 0, pk, 0);
    } else {
      Ed448.generatePrivateKey(random, sk);
      Ed448.generatePublicKey(sk, 0, pk, 0);
    }
    return new byte[][]{sk, pk};
  }

  public void verify(byte[] sig, byte[] pk, byte[] m) throws HsmException {
    boolean sigValid;
    if (this == ED25519) {
      sigValid = Ed25519.verify(sig, 0, pk, 0, m, 0, m.length);
    } else {
      sigValid = Ed448.verify(sig, 0, pk, 0, new byte[0], m, 0, m.length);
    }
    if (!sigValid) {
      throw new HsmException(PKCS11T.CKR_SIGNATURE_INVALID,
          "signature is not valid");
    }
  }

  public byte[] sign(byte[] sk, byte[] m) {
    byte[] sig = new byte[signatureSize];
    if (this == ED25519) {
      Ed25519.sign(sk, 0, m, 0, m.length, sig, 0);
    } else {
      Ed448.sign(sk, 0, new byte[0], m, 0, m.length, sig, 0);
    }
    return sig;
  }

}
