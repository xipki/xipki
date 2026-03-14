// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bridge;

import java.security.PublicKey;
import java.util.Objects;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class MLKEMPublicKey implements PublicKey {

  private final org.bouncycastle.jcajce.interfaces.MLKEMPublicKey bc;

  private final MLKEMParameterSpec parameterSpec;

  public MLKEMPublicKey(org.bouncycastle.jcajce.interfaces.MLKEMPublicKey bc) {
    this.bc = Objects.requireNonNull(bc);
    this.parameterSpec = MLKEMParameterSpec.of(bc.getParameterSpec());
  }

  public MLKEMParameterSpec getParameterSpec() {
    return parameterSpec;
  }

  @Override
  public String getAlgorithm() {
    return bc.getAlgorithm();
  }

  @Override
  public String getFormat() {
    return bc.getFormat();
  }

  @Override
  public byte[] getEncoded() {
    return bc.getEncoded();
  }

  public byte[] getPublicData() {
    return bc.getPublicData();
  }

  org.bouncycastle.jcajce.interfaces.MLKEMPublicKey getBc() {
    return bc;
  }
}
