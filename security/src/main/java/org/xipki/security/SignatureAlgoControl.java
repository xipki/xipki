// Copyright (c) 2013-2023 xipki. All rights reserved.
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

  private final boolean gm;

  public SignatureAlgoControl() {
    this(false, false, false);
  }

  public SignatureAlgoControl(boolean rsaPss, boolean dsaPlain) {
    this(rsaPss, dsaPlain, false);
  }

  public SignatureAlgoControl(boolean rsaPss, boolean dsaPlain, boolean gm) {
    this.rsaPss = rsaPss;
    this.dsaPlain = dsaPlain;
    this.gm = gm;
  }

  public boolean isRsaPss() {
    return rsaPss;
  }

  public boolean isDsaPlain() {
    return dsaPlain;
  }

  public boolean isGm() {
    return gm;
  }

}
