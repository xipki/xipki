// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.client;

/**
 * Exception related to the OCSP requestor.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class OcspRequestorException extends Exception {

  public OcspRequestorException(String message) {
    super(message);
  }

  public OcspRequestorException(String message, Throwable cause) {
    super(message, cause);
  }

}
