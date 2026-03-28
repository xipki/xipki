// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bridge;

import java.security.PrivateKey;
import java.util.Objects;

/**
 * MLDSAPrivate Key.
 *
 * @author Lijun Liao (xipki)
 */
public class MLDSAPrivateKey implements PrivateKey {

  private final org.bouncycastle.pqc.jcajce.interfaces.MLDSAPrivateKey bc;

  private final MLDSAParameterSpec parameterSpec;

  public MLDSAPrivateKey(org.bouncycastle.pqc.jcajce.interfaces.MLDSAPrivateKey bc) {
    this.bc = Objects.requireNonNull(bc);
    this.parameterSpec = MLDSAParameterSpec.of(bc.getParameterSpec());
  }

  public byte[] getSeed() {
    return bc.getSeed();
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

  org.bouncycastle.pqc.jcajce.interfaces.MLDSAPrivateKey getBc() {
    return bc;
  }
}
