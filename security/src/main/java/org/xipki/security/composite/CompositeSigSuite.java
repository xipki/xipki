// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.composite;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;

import java.nio.charset.StandardCharsets;

/**
 * Enumeration of the composite signature algorithms
 * @author Lijun Liao (xipki)
 */
public enum CompositeSigSuite {

  MLDSA44_RSA2048_PSS_SHA256(
      OIDs.Composite.id_MLDSA44_RSA2048_PSS_SHA256,
      "COMPSIG-MLDSA44-RSA2048-PSS-SHA256", HashAlgo.SHA256,
      MldsaVariant.mldsa44, SigTradVariant.RSA2048_PSS),

  MLDSA44_RSA2048_PKCS15_SHA256(
      OIDs.Composite.id_MLDSA44_RSA2048_PKCS15_SHA256,
      "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256", HashAlgo.SHA256,
      MldsaVariant.mldsa44, SigTradVariant.RSA2048_PKCS15),

  MLDSA44_Ed25519_SHA512(
      OIDs.Composite.id_MLDSA44_Ed25519_SHA512,
      "COMPSIG-MLDSA44-Ed25519-SHA512", HashAlgo.SHA512,
      MldsaVariant.mldsa44, SigTradVariant.Ed25519),

  MLDSA44_ECDSA_P256_SHA256(
      OIDs.Composite.id_MLDSA44_ECDSA_P256_SHA256,
      "COMPSIG-MLDSA44-ECDSA-P256-SHA256", HashAlgo.SHA256,
      MldsaVariant.mldsa44, SigTradVariant.ECDSA_P256),

  MLDSA65_RSA3072_PSS_SHA512(
      OIDs.Composite.id_MLDSA65_RSA3072_PSS_SHA512,
      "COMPSIG-MLDSA65-RSA3072-PSS-SHA512", HashAlgo.SHA512,
      MldsaVariant.mldsa65, SigTradVariant.RSA3072_PSS),

  MLDSA65_RSA3072_PKCS15_SHA512(
      OIDs.Composite.id_MLDSA65_RSA3072_PKCS15_SHA512,
      "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512", HashAlgo.SHA512,
      MldsaVariant.mldsa65, SigTradVariant.RSA3072_PKCS15),

  MLDSA65_RSA4096_PSS_SHA512(
      OIDs.Composite.id_MLDSA65_RSA4096_PSS_SHA512,
      "COMPSIG-MLDSA65-RSA4096-PSS-SHA512", HashAlgo.SHA512,
      MldsaVariant.mldsa65, SigTradVariant.RSA4096_PSS),

  MLDSA65_RSA4096_PKCS15_SHA512(
      OIDs.Composite.id_MLDSA65_RSA4096_PKCS15_SHA512,
      "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512", HashAlgo.SHA512,
      MldsaVariant.mldsa65, SigTradVariant.RSA4096_PKCS15),

  MLDSA65_ECDSA_P256_SHA512(
      OIDs.Composite.id_MLDSA65_ECDSA_P256_SHA512,
      "COMPSIG-MLDSA65-ECDSA-P256-SHA512", HashAlgo.SHA512,
      MldsaVariant.mldsa65, SigTradVariant.ECDSA_P256),

  MLDSA65_ECDSA_P384_SHA512(
      OIDs.Composite.id_MLDSA65_ECDSA_P384_SHA512,
      "COMPSIG-MLDSA65-ECDSA-P384-SHA512", HashAlgo.SHA512,
      MldsaVariant.mldsa65, SigTradVariant.ECDSA_P384),

  MLDSA65_ECDSA_BP256_SHA512(
      OIDs.Composite.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512,
      "COMPSIG-MLDSA65-ECDSA-BP256-SHA512", HashAlgo.SHA512,
      MldsaVariant.mldsa65, SigTradVariant.ECDSA_BP256),

  MLDSA65_Ed25519_SHA512(
      OIDs.Composite.id_MLDSA65_Ed25519_SHA512,
      "COMPSIG-MLDSA65-Ed25519-SHA512", HashAlgo.SHA512,
      MldsaVariant.mldsa65, SigTradVariant.Ed25519),

  MLDSA87_ECDSA_P384_SHA512(
      OIDs.Composite.id_MLDSA87_ECDSA_P384_SHA512,
      "COMPSIG-MLDSA87-ECDSA-P384-SHA512", HashAlgo.SHA512,
      MldsaVariant.mldsa87, SigTradVariant.ECDSA_P384),

  MLDSA87_ECDSA_BP384_SHA512(
      OIDs.Composite.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512,
      "COMPSIG-MLDSA87-ECDSA-BP384-SHA512", HashAlgo.SHA512,
      MldsaVariant.mldsa87, SigTradVariant.ECDSA_BP384),

  MLDSA87_Ed448_SHAKE256(
      OIDs.Composite.id_MLDSA87_Ed448_SHAKE256,
      "COMPSIG-MLDSA87-Ed448-SHAKE256", HashAlgo.SHAKE256,
      MldsaVariant.mldsa87, SigTradVariant.Ed448),

  MLDSA87_RSA3072_PSS_SHA512(
      OIDs.Composite.id_MLDSA87_RSA3072_PSS_SHA512,
      "COMPSIG-MLDSA87-RSA3072-PSS-SHA512", HashAlgo.SHA512,
      MldsaVariant.mldsa87, SigTradVariant.RSA3072_PSS),

  MLDSA87_RSA4096_PSS_SHA512(
      OIDs.Composite.id_MLDSA87_RSA4096_PSS_SHA512,
      "COMPSIG-MLDSA87-RSA4096-PSS-SHA512", HashAlgo.SHA512,
      MldsaVariant.mldsa87, SigTradVariant.RSA4096_PSS),

  MLDSA87_ECDSA_P521_SHA512(
      OIDs.Composite.id_MLDSA87_ECDSA_P521_SHA512,
      "COMPSIG-MLDSA87-ECDSA-P521-SHA512", HashAlgo.SHA512,
      MldsaVariant.mldsa87, SigTradVariant.ECDSA_P521);

  private final ASN1ObjectIdentifier oid;

  private final AlgorithmIdentifier algId;

  private final HashAlgo ph;

  private final MldsaVariant mldsaVariant;

  private final SigTradVariant tradVariant;

  private final KeySpec keySpec;

  private final byte[] label;

  CompositeSigSuite(ASN1ObjectIdentifier oid,
                    String label, HashAlgo ph,
                    MldsaVariant mldsaVariant, SigTradVariant tradVariant) {
    this.label = label.getBytes(StandardCharsets.UTF_8);
    this.oid = oid;
    this.algId = new AlgorithmIdentifier(oid);
    this.ph = ph;
    this.mldsaVariant = mldsaVariant;
    this.tradVariant = tradVariant;
    this.keySpec = KeySpec.ofAlgorithmIdentifier(algId);
  }

  public static CompositeSigSuite ofOid(ASN1ObjectIdentifier oid) {
    for (CompositeSigSuite as : CompositeSigSuite.values()) {
      if (as.oid.equals(oid)) {
        return as;
      }
    }
    return null;
  }

  public ASN1ObjectIdentifier oid() {
    return oid;
  }

  public KeySpec keySpec() {
    return keySpec;
  }

  public AlgorithmIdentifier algId() {
    return algId;
  }

  public MldsaVariant mldsaVariant() {
    return mldsaVariant;
  }

  public SigTradVariant tradVariant() {
    return tradVariant;
  }

  public HashAlgo ph() {
    return ph;
  }

  public byte[] label() {
    return label;
  }

}
