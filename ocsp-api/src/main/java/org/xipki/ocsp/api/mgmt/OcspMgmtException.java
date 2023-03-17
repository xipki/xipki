// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.api.mgmt;

/**
 * OCSP management exception.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class OcspMgmtException extends Exception {

  public OcspMgmtException() {
  }

  public OcspMgmtException(String message, Throwable cause) {
    super(message, cause);
  }

  public OcspMgmtException(String message) {
    super(message);
  }

  public OcspMgmtException(Throwable cause) {
    super(cause.getMessage(), cause);
  }

}
