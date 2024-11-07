// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

/**
 * Control the signature algorithm.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class SignatureAlgoControl {

  private final boolean rsaPss;

  private final boolean dsaPlain;

  public SignatureAlgoControl() {
    this(false, false);
  }

  public SignatureAlgoControl(boolean rsaPss, boolean dsaPlain) {
    this.rsaPss = rsaPss;
    this.dsaPlain = dsaPlain;
  }

  public boolean isRsaPss() {
    return rsaPss;
  }

  public boolean isDsaPlain() {
    return dsaPlain;
  }

}
