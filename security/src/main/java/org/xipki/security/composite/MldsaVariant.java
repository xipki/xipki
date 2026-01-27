// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.composite;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.xipki.security.KeySpec;
import org.xipki.security.SignAlgo;

/**
 * Enumeration of MLDSA algorithms used in {@link CompositeSigSuite}.
 * @author Lijun Liao (xipki)
 */
public enum MldsaVariant {

  mldsa44(SignAlgo.MLDSA44, KeySpec.MLDSA44),
  mldsa65(SignAlgo.MLDSA65, KeySpec.MLDSA65),
  mldsa87(SignAlgo.MLDSA87, KeySpec.MLDSA87);

  private final SignAlgo signAlgo;
  private final KeySpec keySpec;
  private final int skSize;
  private final int pkSize;
  private final int sigSize;
  private final MLDSAParameters params;

  MldsaVariant(SignAlgo signAlgo, KeySpec keySpec) {
    this.signAlgo = signAlgo;
    this.keySpec = keySpec;
    switch (keySpec) {
      case MLDSA44: {
        skSize = 32;
        pkSize = 1312;
        sigSize = 2420;
        params = MLDSAParameters.ml_dsa_44;
        break;
      }
      case MLDSA65: {
        skSize = 32;
        pkSize = 1952;
        sigSize = 3309;
        params = MLDSAParameters.ml_dsa_65;
        break;
      }
      case MLDSA87: {
        skSize = 32;
        pkSize = 2592;
        sigSize = 4627;
        params = MLDSAParameters.ml_dsa_87;
        break;
      }
      default:
        throw new IllegalArgumentException("invalid keyType " + keySpec);
    }
  }

  public SignAlgo signAlgo() {
    return signAlgo;
  }

  public KeySpec keySpec() {
    return keySpec;
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
