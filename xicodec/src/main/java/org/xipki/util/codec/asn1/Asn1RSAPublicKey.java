// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.codec.asn1;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;

import java.security.spec.InvalidKeySpecException;

/**
 * <pre>
 * RSAPublicKey ::= SEQUENCE {
 *   modulus         INTEGER, -- n
 *   publicExponent  INTEGER  -- e
 *  }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1RSAPublicKey {

  private final byte[] modulus;

  private final byte[] publicExponent;

  public Asn1RSAPublicKey(byte[] modulus, byte[] publicExponent) {
    this.modulus = Args.notNull(modulus, "modulus");
    this.publicExponent = Args.notNull(publicExponent, "publicExponent");
  }

  public byte[] getModulus() {
    return modulus;
  }

  public byte[] getPublicExponent() {
    return publicExponent;
  }

  public static Asn1RSAPublicKey getInstance(byte[] encoded)
      throws InvalidKeySpecException {
    byte[][] bns;
    try {
      bns = Asn1Util.readBigInts(encoded, 2);
    } catch (CodecException e) {
      throw new InvalidKeySpecException(
          "invalid RSAPublicKey: " + e.getMessage(), e);
    }
    return new Asn1RSAPublicKey(bns[0], bns[1]);
  }

}
