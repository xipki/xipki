// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.ca.sdk.jacob.CborEncodable;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public abstract class OldCertInfo implements CborEncodable {

  /**
   * Whether to reu-use the public key in the old certificate for the new one.
   */
  private final boolean reusePublicKey;

  public OldCertInfo(boolean reusePublicKey) {
    this.reusePublicKey = reusePublicKey;
  }

  public boolean isReusePublicKey() {
    return reusePublicKey;
  }

}
