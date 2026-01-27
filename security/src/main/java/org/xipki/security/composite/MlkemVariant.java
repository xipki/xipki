// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.composite;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;

/**
 * @author Lijun Liao (xipki)
 */
public enum MlkemVariant {

  mlkem768(KeySpec.MLKEM768),
  mlkem1024(KeySpec.MLKEM1024);

  private final KeySpec keySpec;
  private final ASN1ObjectIdentifier oid;
  private final int skSize;
  private final int pkSize;
  private final int ctSize;
  private final MLKEMParameters params;

  MlkemVariant(KeySpec keySpec) {
    this.keySpec = keySpec;
    switch (keySpec) {
      case MLKEM768: {
        skSize = 64;
        pkSize = 1184;
        ctSize = 1088;
        params = MLKEMParameters.ml_kem_768;
        oid = OIDs.Algo.id_ml_kem_768;
        break;
      }
      case MLKEM1024: {
        skSize = 64;
        pkSize = 1568;
        ctSize = 1568;
        params = MLKEMParameters.ml_kem_1024;
        oid = OIDs.Algo.id_ml_kem_1024;
        break;
      }
      default:
        throw new IllegalArgumentException("invalid keySpec " + keySpec);
    }
  }

  public KeySpec keySpec() {
    return keySpec;
  }

  public ASN1ObjectIdentifier oid() {
    return oid;
  }

  public int skSize() {
    return skSize;
  }

  public int pkSize() {
    return pkSize;
  }

  public int ctSize() {
    return ctSize;
  }

  public MLKEMParameters params() {
    return params;
  }
}
