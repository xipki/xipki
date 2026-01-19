// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.xipki.pkcs11.wrapper.attrs.Template;

import java.math.BigInteger;
import java.util.Objects;

/**
 * PKCS#11 key
 *
 * @author Lijun Liao (xipki)
 */

public class PKCS11Key {

  protected final PKCS11KeyId id;

  private final Boolean sign;

  private final Boolean verify;

  private final Boolean encrypt;

  private final Boolean decrypt;

  private final Boolean derive;

  private final Boolean signRecover;

  private final Boolean verifyRecover;

  private final Boolean wrap;

  private final Boolean unwrap;

  private final Boolean extractable;

  private final Boolean neverExtractable;

  private final Boolean private_;

  private final Boolean wrapWithTrusted;

  private final Boolean sensitive;

  private final Boolean alwaysSensitive;

  private final Boolean trusted;

  private final Integer valueLen;

  private final byte[] ecParams;

  private final Integer ecOrderBitSize;

  private final byte[] ecPublicPoint;

  private final BigInteger rsaModulus;

  private final BigInteger rsaPublicExponent;

  private final BigInteger dsaPrime;

  private final BigInteger dsaSubprime;

  private final BigInteger dsaBase;

  private final Long pqcVariant;

  PKCS11Key(PKCS11KeyId id, Template attrs) {
    this.id = Objects.requireNonNull(id, "id must not be null");
    // purposes
    this.decrypt = attrs.decrypt();
    this.encrypt = attrs.encrypt();
    this.sign = attrs.sign();
    this.verify = attrs.verify();
    this.signRecover = attrs.signRecover();
    this.verifyRecover = attrs.verifyRecover();
    this.wrap = attrs.wrap();
    this.unwrap = attrs.unwrap();
    this.derive = attrs.derive();

    this.sensitive = attrs.sensitive();
    this.alwaysSensitive = attrs.alwaysSensitive();
    this.extractable = attrs.extractable();
    this.neverExtractable = attrs.neverExtractable();
    this.private_ = attrs.private_();

    this.trusted = attrs.trusted();
    this.wrapWithTrusted = attrs.wrapWithTrusted();

    // Secret Key attributes
    this.valueLen = attrs.valueLen();

    // RSA Key attributes
    this.rsaModulus = attrs.modulus();
    this.rsaPublicExponent = attrs.publicExponent();

    // DSA Key attributes
    this.dsaPrime = attrs.prime();
    this.dsaSubprime = attrs.subprime();
    this.dsaBase = attrs.base();

    // EC Key attributes
    this.ecPublicPoint = attrs.ecPoint();
    this.ecParams = attrs.ecParams();
    if (ecParams == null) {
      this.ecOrderBitSize = null;
    } else {
      this.ecOrderBitSize = Functions.getCurveOrderBitLength(ecParams);
    }

    // PQC key attributes
    this.pqcVariant = attrs.parameterSet();
  }

  public PKCS11KeyId id() {
    return id;
  }

  public Boolean sign() {
    return sign;
  }

  public Boolean verify() {
    return verify;
  }

  public Boolean encrypt() {
    return encrypt;
  }

  public Boolean decrypt() {
    return decrypt;
  }

  public Boolean derive() {
    return derive;
  }

  public Boolean signRecover() {
    return signRecover;
  }

  public Boolean verifyRecover() {
    return verifyRecover;
  }

  public Boolean wrap() {
    return wrap;
  }

  public Boolean unwrap() {
    return unwrap;
  }

  public Boolean extractable() {
    return extractable;
  }

  public Boolean neverExtractable() {
    return neverExtractable;
  }

  public Boolean private_() {
    return private_;
  }

  public Boolean wrapWithTrusted() {
    return wrapWithTrusted;
  }

  public Boolean sensitive() {
    return sensitive;
  }

  public Boolean alwaysSensitive() {
    return alwaysSensitive;
  }

  public Boolean trusted() {
    return trusted;
  }

  public Integer valueLen() {
    return valueLen;
  }

  public byte[] ecParams() {
    return ecParams;
  }

  public Integer ecOrderBitSize() {
    return ecOrderBitSize;
  }

  public byte[] ecPublicPoint() {
    return ecPublicPoint;
  }

  public BigInteger rsaModulus() {
    return rsaModulus;
  }

  public BigInteger rsaPublicExponent() {
    return rsaPublicExponent;
  }

  public BigInteger dsaPrime() {
    return dsaPrime;
  }

  public BigInteger dsaSubprime() {
    return dsaSubprime;
  }

  public BigInteger dsaBase() {
    return dsaBase;
  }

  public Long pqcVariant() {
    return pqcVariant;
  }

}
