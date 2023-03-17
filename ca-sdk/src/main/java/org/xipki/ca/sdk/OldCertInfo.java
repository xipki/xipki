// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class OldCertInfo {

  /**
   * Whether to reu-use the public key in the old certificate for the new one.
   */
  private boolean reusePublicKey;

  public boolean isReusePublicKey() {
    return reusePublicKey;
  }

  public void setReusePublicKey(boolean reusePublicKey) {
    this.reusePublicKey = reusePublicKey;
  }
}
