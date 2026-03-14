// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bridge;

import java.util.Objects;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class AsymmetricCipherKeyPair extends org.bouncycastle.pqc.crypto.AsymmetricCipherKeyPair {

  public AsymmetricCipherKeyPair(org.bouncycastle.pqc.crypto.AsymmetricCipherKeyPair bc) {
    super(Objects.requireNonNull(bc).getPublic(), bc.getPrivate());
  }

}
