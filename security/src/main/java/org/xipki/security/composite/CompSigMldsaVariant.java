// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.composite;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.xipki.security.KeySpec;
import org.xipki.security.SignAlgo;

/**
 * Enumeration of MLDSA algorithms used in {@link CompositeSigSuite}.
 * @author Lijun Liao (xipki)
 */
public enum CompSigMldsaVariant {

  mldsa44(32, 1312, 2420, MLDSAParameters.ml_dsa_44),
  mldsa65(32, 1952, 3309, MLDSAParameters.ml_dsa_65),
  mldsa87(32, 2592, 4627, MLDSAParameters.ml_dsa_87);

  private final int skSize;
  private final int pkSize;
  private final int sigSize;
  private final MLDSAParameters params;

  CompSigMldsaVariant(int skSize, int pkSize, int sigSize, MLDSAParameters params) {
    this.skSize = skSize;
    this.pkSize = pkSize;
    this.sigSize = sigSize;
    this.params = params;
  }

  public SignAlgo signAlgo() {
    switch (this) {
      case mldsa44:
        return SignAlgo.MLDSA44;
      case mldsa65:
        return SignAlgo.MLDSA65;
      default:
        return SignAlgo.MLDSA87;
    }
  }

  public KeySpec keySpec() {
    switch (this) {
      case mldsa44:
        return KeySpec.MLDSA44;
      case mldsa65:
        return KeySpec.MLDSA65;
      default:
        return KeySpec.MLDSA87;
    }
  }

  public int skSize() {
    return skSize;
  }

  public int pkSize() {
    return pkSize;
  }

  public int sigSize() {
    return sigSize;
  }

  public MLDSAParameters params() {
    return params;
  }
}
