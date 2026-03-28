// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bridge;

import java.util.Locale;
import java.util.Objects;

/**
 * MLDSAParameter Spec.
 *
 * @author Lijun Liao (xipki)
 */
public class MLDSAParameterSpec {

  public static final MLDSAParameterSpec ml_dsa_44 = new MLDSAParameterSpec(
      org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44);

  public static final MLDSAParameterSpec ml_dsa_65 = new MLDSAParameterSpec(
      org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_65);

  public static final MLDSAParameterSpec ml_dsa_87 = new MLDSAParameterSpec(
      org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_87);

  private final org.bouncycastle.jcajce.spec.MLDSAParameterSpec bc;

  private MLDSAParameterSpec(org.bouncycastle.jcajce.spec.MLDSAParameterSpec bc) {
    this.bc = Objects.requireNonNull(bc);
  }

  static MLDSAParameterSpec of(org.bouncycastle.jcajce.spec.MLDSAParameterSpec bc) {
    switch (bc.getName().toUpperCase(Locale.ROOT).replace("-", "").replace("_", "")) {
      case "MLDSA44":
        return ml_dsa_44;
      case "MLDSA65":
        return ml_dsa_65;
      case "MLDSA87":
        return ml_dsa_87;
      default:
        throw new IllegalArgumentException("invalid MLDSAParameterSpec " + bc.getName());
    }
  }

  public String getName() {
    return bc.getName();
  }

  public org.bouncycastle.jcajce.spec.MLDSAParameterSpec getBc() {
    return bc;
  }

}
