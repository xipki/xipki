// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.operator.ContentSigner;

/**
 * Extends {@link ContentSigner} by a new method {@link #getEncodedAlgorithmIdentifier()}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public interface XiContentSigner extends ContentSigner {

  /**
   * returns the encoded algorithm identifier.
   * @return the encoded algorithm identifier.
   */
  byte[] getEncodedAlgorithmIdentifier();

}
