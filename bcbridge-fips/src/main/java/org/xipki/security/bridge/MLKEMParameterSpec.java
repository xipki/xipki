// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bridge;

import java.util.Locale;
import java.util.Objects;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class MLKEMParameterSpec {

  public static final MLKEMParameterSpec ml_kem_512 = new MLKEMParameterSpec(
          org.bouncycastle.pqc.jcajce.spec.MLKEMParameterSpec.ml_kem_512);

  public static final MLKEMParameterSpec ml_kem_768 = new MLKEMParameterSpec(
          org.bouncycastle.pqc.jcajce.spec.MLKEMParameterSpec.ml_kem_768);

  public static final MLKEMParameterSpec ml_kem_1024 = new MLKEMParameterSpec(
          org.bouncycastle.pqc.jcajce.spec.MLKEMParameterSpec.ml_kem_1024);

  private final org.bouncycastle.pqc.jcajce.spec.MLKEMParameterSpec bc;

  private MLKEMParameterSpec(org.bouncycastle.pqc.jcajce.spec.MLKEMParameterSpec bc) {
    this.bc = Objects.requireNonNull(bc);
  }

  public String getName() {
    return bc.getName();
  }

  org.bouncycastle.pqc.jcajce.spec.MLKEMParameterSpec getBc() {
    return bc;
  }

  static MLKEMParameterSpec of(org.bouncycastle.pqc.jcajce.spec.MLKEMParameterSpec bc) {
    switch (bc.getName().toUpperCase(Locale.ROOT)
        .replace("-", "").replace("_", "")) {
      case "MLKEM512":
        return ml_kem_512;
      case "MLKEM768":
        return ml_kem_768;
      case "MLKEM1024":
        return ml_kem_1024;
      default:
        throw new IllegalArgumentException("invalid MLKEMParameterSpec " + bc.getName());
    }
  }

}
