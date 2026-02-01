// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.operator.ContentSigner;
import org.xipki.security.exception.XiSecurityException;

import java.io.IOException;

/**
 * Extends {@link ContentSigner} by a new method
 * {@link #getEncodedX509AlgId()}.
 *
 * @author Lijun Liao (xipki)
 */

public interface XiSigner {

  default byte[] x509Sign(byte[] data) throws XiSecurityException {
    try {
      ContentSigner signer = x509Signer();
      signer.getOutputStream().write(data);
      return signer.getSignature();
    } catch (RuntimeException | IOException e) {
      throw new XiSecurityException(e);
    }
  }

  ContentSigner x509Signer();

  /**
   * returns the encoded algorithm identifier.
   * @return the encoded algorithm identifier.
   */
  byte[] getEncodedX509AlgId();

}
