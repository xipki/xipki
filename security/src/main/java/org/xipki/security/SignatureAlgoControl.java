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

  public SignatureAlgoControl() {
    this(false);
  }

  public SignatureAlgoControl(boolean rsaPss) {
    this.rsaPss = rsaPss;
  }

  public boolean isRsaPss() {
    return rsaPss;
  }

}
