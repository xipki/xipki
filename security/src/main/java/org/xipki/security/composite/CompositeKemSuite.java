// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.composite;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;

import java.nio.charset.StandardCharsets;

/**
 * @author Lijun Liao (xipki)
 */
public enum CompositeKemSuite {

  MLKEM768_RSA2048_SHA3_256(
      OIDs.Composite.id_MLKEM768_RSA2048_SHA3_256,
      "MLKEM768-RSAOAEP2048",
      MlkemVariant.mlkem768, KemTradVariant.RSA2048_OAEP),

  MLKEM768_RSA3072_SHA3_256(
      OIDs.Composite.id_MLKEM768_RSA3072_SHA3_256,
      "MLKEM768-RSAOAEP3072",
      MlkemVariant.mlkem768, KemTradVariant.RSA3072_OAEP),

  MLKEM768_RSA4096_SHA3_256(
      OIDs.Composite.id_MLKEM768_RSA4096_SHA3_256,
      "MLKEM768-RSAOAEP4096",
      MlkemVariant.mlkem768, KemTradVariant.RSA4096_OAEP),

  MLKEM768_X25519_SHA3_256(
        OIDs.Composite.id_MLKEM768_X25519_SHA3_256,
        "\\.//^\\", // "\.//^\"
        MlkemVariant.mlkem768, KemTradVariant.X25519),

  MLKEM768_ECDH_P256_SHA3_256(
      OIDs.Composite.id_MLKEM768_ECDH_P256_SHA3_256,
      "MLKEM768-P256",
      MlkemVariant.mlkem768, KemTradVariant.ECDH_P256),

  MLKEM768_ECDH_P384_SHA3_256(
      OIDs.Composite.id_MLKEM768_ECDH_P384_SHA3_256,
      "MLKEM768-P384",
      MlkemVariant.mlkem768, KemTradVariant.ECDH_P384),

  MLKEM768_ECDH_BRAINPOOLP256R1_SHA3_256(
      OIDs.Composite.id_MLKEM768_ECDH_brainpoolP256r1_SHA3_256,
      "MLKEM768-BP256",
      MlkemVariant.mlkem768, KemTradVariant.ECDH_BP256),

  MLKEM1024_RSA3072_SHA3_256(
      OIDs.Composite.id_MLKEM1024_RSA3072_SHA3_256,
      "MLKEM1024-RSAOAEP3072",
      MlkemVariant.mlkem1024, KemTradVariant.RSA3072_OAEP),

  MLKEM1024_ECDH_P384_SHA3_256(
      OIDs.Composite.id_MLKEM1024_ECDH_P384_SHA3_256,
      "MLKEM1024-P384",
      MlkemVariant.mlkem1024, KemTradVariant.ECDH_P384),

  MLKEM1024_ECDH_BRAINPOOLP384R1_SHA3_256(
      OIDs.Composite.id_MLKEM1024_ECDH_brainpoolP384r1_SHA3_256,
      "MLKEM1024-BP384",
      MlkemVariant.mlkem1024, KemTradVariant.ECDH_BP384),

  MLKEM1024_X448_SHA3_256(
      OIDs.Composite.id_MLKEM1024_X448_SHA3_256,
      "MLKEM1024-X448",
      MlkemVariant.mlkem1024, KemTradVariant.X448),

  MLKEM1024_ECDH_P521_SHA3_256(
      OIDs.Composite.id_MLKEM1024_ECDH_P521_SHA3_256,
      "MLKEM1024-P521",
      MlkemVariant.mlkem1024, KemTradVariant.ECDH_P521);

  private final AlgorithmIdentifier algId;
  private final ASN1ObjectIdentifier oid;
  private final byte[] label;
  private final MlkemVariant mlkemVariant;
  private final KemTradVariant tradVariant;
  private final KeySpec keySpec;

  CompositeKemSuite(ASN1ObjectIdentifier oid, String label,
                    MlkemVariant mlkemVariant, KemTradVariant tradVariant) {
    this.oid = oid;
    this.algId = new AlgorithmIdentifier(oid);
    this.label = label.getBytes(StandardCharsets.US_ASCII);
    this.mlkemVariant = mlkemVariant;
    this.tradVariant = tradVariant;
    this.keySpec = KeySpec.ofAlgorithmIdentifier(algId);
  }

  public static CompositeKemSuite ofVariants(
      MlkemVariant mlkemVariant, KemTradVariant tradVariant) {
    for (CompositeKemSuite as : CompositeKemSuite.values()) {
      if (as.mlkemVariant == mlkemVariant && as.tradVariant == tradVariant) {
        return as;
      }
    }
    return null;
  }

  public static CompositeKemSuite ofKeySpecs(
      KeySpec mlkemKeySpec, KeySpec tradKeySpec) {
    for (CompositeKemSuite as : CompositeKemSuite.values()) {
      if (as.mlkemVariant.keySpec() == mlkemKeySpec
          && as.tradVariant.keySpec() == tradKeySpec) {
        return as;
      }
    }
    return null;
  }

  public static CompositeKemSuite getAlgoSuite(ASN1ObjectIdentifier oid) {
    for (CompositeKemSuite as : CompositeKemSuite.values()) {
      if (as.oid.equals(oid)) {
        return as;
      }
    }
    return null;
  }

  public static CompositeKemSuite getAlgoSuite(AlgorithmIdentifier algId) {
    ASN1Encodable params = algId.getParameters();
    if (params != null && params != DERNull.INSTANCE) {
      return null;
    }

    return getAlgoSuite(algId.getAlgorithm());
  }

  public AlgorithmIdentifier algId() {
    return algId;
  }

  public MlkemVariant mlkemVariant() {
    return mlkemVariant;
  }

  public KemTradVariant tradVariant() {
    return tradVariant;
  }

  public KeySpec keySpec() {
    return keySpec;
  }

  public byte[] label() {
    return label.clone();
  }

}
