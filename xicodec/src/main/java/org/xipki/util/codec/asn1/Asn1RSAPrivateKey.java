// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.util.codec.asn1;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;

import java.security.spec.InvalidKeySpecException;

/**
 * <pre>
 * RSAPrivateKey ::= SEQUENCE {
 *     version           Version,
 *     modulus           INTEGER,  -- n
 *     publicExponent    INTEGER,  -- e
 *     privateExponent   INTEGER,  -- d
 *     prime1            INTEGER,  -- p
 *     prime2            INTEGER,  -- q
 *     exponent1         INTEGER,  -- d mod (p-1)
 *     exponent2         INTEGER,  -- d mod (q-1)
 *     coefficient       INTEGER,  -- (inverse of q) mod p
 *     otherPrimeInfos   OtherPrimeInfos OPTIONAL
 * }
 *
 * Version ::= INTEGER { two-prime(0), multi(1) }
 *                (CONSTRAINED BY
 *                {-- version must be multi if otherPrimeInfos present --})
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1RSAPrivateKey {

  private final byte[] modulus;

  private final byte[] publicExponent;

  private final byte[] privateExponent;

  private final byte[] prime1;

  private final byte[] prime2;

  private final byte[] exponent1;

  private final byte[] exponent2;

  private final byte[] coefficient;

  public Asn1RSAPrivateKey(
      byte[] modulus, byte[] publicExponent, byte[] privateExponent,
      byte[] prime1, byte[] prime2, byte[] exponent1,
      byte[] exponent2, byte[] coefficient) {
    this.modulus = Args.notNull(modulus, "modulus");
    this.publicExponent = Args.notNull(publicExponent, "publicExponent");
    this.privateExponent = Args.notNull(privateExponent, "privateExponent");
    this.prime1 = Args.notNull(prime1,  "prime1");
    this.prime2 = Args.notNull(prime2, "prime2");
    this.exponent1 = Args.notNull(exponent1, "exponent1");
    this.exponent2 = Args.notNull(exponent2, "exponent2");
    this.coefficient = Args.notNull(coefficient, "coefficient");
  }

  public byte[] getModulus() {
    return modulus;
  }

  public byte[] getPublicExponent() {
    return publicExponent;
  }

  public byte[] getPrivateExponent() {
    return privateExponent;
  }

  public byte[] getPrime1() {
    return prime1;
  }

  public byte[] getPrime2() {
    return prime2;
  }

  public byte[] getExponent1() {
    return exponent1;
  }

  public byte[] getExponent2() {
    return exponent2;
  }

  public byte[] getCoefficient() {
    return coefficient;
  }

  public static Asn1RSAPrivateKey getInstance(byte[] encoded)
      throws InvalidKeySpecException {
    byte[][] bns;
    try {
      bns = Asn1Util.readBigInts(encoded, 9);
    } catch (CodecException e) {
      throw new InvalidKeySpecException(
          "invalid RSAPrivateKey: " + e.getMessage(), e);
    }

    int off = 1;
    return new Asn1RSAPrivateKey(
        bns[off++], bns[off++], bns[off++], bns[off++],
        bns[off++], bns[off++], bns[off++], bns[off]);
  }

}
