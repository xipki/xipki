// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.client;

import org.xipki.pkix.exception.PkixException;

/**
 * OCSP Requestor Exception type.
 *
 * @author Lijun Liao (xipki)
 */
public class OcspRequestorException extends PkixException {

  public OcspRequestorException(String message) {
    super(message);
  }

  public OcspRequestorException(String message, Throwable cause) {
    super(message, cause);
  }

}
