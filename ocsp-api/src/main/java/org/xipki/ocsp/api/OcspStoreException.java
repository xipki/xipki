// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.api;

/**
 * OCSP store exception.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class OcspStoreException extends Exception {

  public OcspStoreException() {
  }

  public OcspStoreException(String message) {
    super(message);
  }

  public OcspStoreException(Throwable cause) {
    super(cause);
  }

  public OcspStoreException(String message, Throwable cause) {
    super(message, cause);
  }

}
