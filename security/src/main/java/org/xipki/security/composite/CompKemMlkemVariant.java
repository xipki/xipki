// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.composite;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public enum CompKemMlkemVariant {

  mlkem768(64, 1184, 1088, MLKEMParameters.ml_kem_768, OIDs.Algo.id_ml_kem_768),
  mlkem1024(64, 1568, 1568, MLKEMParameters.ml_kem_1024, OIDs.Algo.id_ml_kem_1024);

  private final ASN1ObjectIdentifier oid;
  private final int skSize;
  private final int pkSize;
  private final int ctSize;
  private final MLKEMParameters params;

  CompKemMlkemVariant(int skSize, int pkSize, int ctSize,
                      MLKEMParameters params, ASN1ObjectIdentifier oid) {
    this.skSize = skSize;
    this.pkSize = pkSize;
    this.ctSize = ctSize;
    this.params = params;
    this.oid = oid;
  }

  public KeySpec keySpec() {
    return (this == CompKemMlkemVariant.mlkem768) ? KeySpec.MLKEM768 : KeySpec.MLKEM1024;
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
