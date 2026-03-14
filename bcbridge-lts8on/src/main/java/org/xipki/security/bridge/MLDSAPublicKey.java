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
public class MLDSAPublicKey implements PublicKey {

  private final org.bouncycastle.jcajce.interfaces.MLDSAPublicKey bc;

  private final MLDSAParameterSpec parameterSpec;

  public MLDSAPublicKey(org.bouncycastle.jcajce.interfaces.MLDSAPublicKey bc) {
    this.bc = Objects.requireNonNull(bc);
    this.parameterSpec = MLDSAParameterSpec.of(bc.getParameterSpec());
  }

  public MLDSAParameterSpec getParameterSpec() {
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

  org.bouncycastle.jcajce.interfaces.MLDSAPublicKey getBc() {
    return bc;
  }

}
