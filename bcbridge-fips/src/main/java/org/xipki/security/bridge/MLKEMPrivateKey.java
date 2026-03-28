// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bridge;

import java.security.PrivateKey;
import java.util.Objects;

/**
 * MLKEMPrivate Key.
 *
 * @author Lijun Liao (xipki)
 */
public class MLKEMPrivateKey implements PrivateKey {

  private final org.bouncycastle.pqc.jcajce.interfaces.MLKEMPrivateKey bc;

  private final MLKEMParameterSpec parameterSpec;

  public MLKEMPrivateKey(org.bouncycastle.pqc.jcajce.interfaces.MLKEMPrivateKey bc) {
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

  public byte[] getSeed() {
    return bc.getSeed();
  }

  org.bouncycastle.pqc.jcajce.interfaces.MLKEMPrivateKey getBc() {
    return bc;
  }
}
