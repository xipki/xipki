// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.xipki.pkcs11.wrapper.PKCS11T;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * @author Lijun Liao (xipki)
 */
public class XiConstants {

  public enum P11MldsaVariant {

    MLDSA44(PKCS11T.CKP_ML_DSA_44,
        NISTObjectIdentifiers.id_ml_dsa_44),

    MLDSA65(PKCS11T.CKP_ML_DSA_65,
        NISTObjectIdentifiers.id_ml_dsa_65),

    MLDSA87(PKCS11T.CKP_ML_DSA_87,
        NISTObjectIdentifiers.id_ml_dsa_87);

    private final long code;

    private final ASN1ObjectIdentifier oid;

    P11MldsaVariant(long code, ASN1ObjectIdentifier oid) {
      this.code = code;
      this.oid = oid;
    }

    public long getCode() {
      return code;
    }

    public ASN1ObjectIdentifier getOid() {
      return oid;
    }

    public KeyPair generateKeyPair() throws HsmException {
      try {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(oid.getId());
        return gen.generateKeyPair();
      } catch (Exception e) {
        throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
            "error generating keypair " + name(), e);
      }
    }

    public static P11MldsaVariant ofCode(long code) throws HsmException {
      for (P11MldsaVariant variant : P11MldsaVariant.values()) {
        if (code == variant.code) {
          return variant;
        }
      }

      throw new HsmException(PKCS11T.CKR_ATTRIBUTE_VALUE_INVALID,
          "unknown MLDSA variant " + code);
    }

  }

  public enum P11MlkemVariant {

    MLKEM512 (PKCS11T.CKP_ML_KEM_512, NISTObjectIdentifiers.id_alg_ml_kem_512),

    MLKEM768 (PKCS11T.CKP_ML_KEM_768, NISTObjectIdentifiers.id_alg_ml_kem_768),

    MLKEM1024(PKCS11T.CKP_ML_KEM_1024,
        NISTObjectIdentifiers.id_alg_ml_kem_1024);

    private final long code;

    private final ASN1ObjectIdentifier oid;

    P11MlkemVariant(long code, ASN1ObjectIdentifier oid) {
      this.code = code;
      this.oid = oid;
    }

    public long getCode() {
      return code;
    }

    public ASN1ObjectIdentifier getOid() {
      return oid;
    }

    public static P11MlkemVariant ofOid(String oid) {
      for (P11MlkemVariant v : P11MlkemVariant.values()) {
        if (v.oid.getId().equals(oid)) {
          return v;
        }
      }
      return null;
    }

    public static P11MlkemVariant ofCode(long code) throws HsmException {
      for (P11MlkemVariant variant : P11MlkemVariant.values()) {
        if (code == variant.code) {
          return variant;
        }
      }

      throw new HsmException(PKCS11T.CKR_ATTRIBUTE_VALUE_INVALID,
          "unknown MLKEM variant " + code);
    }

  }

}
