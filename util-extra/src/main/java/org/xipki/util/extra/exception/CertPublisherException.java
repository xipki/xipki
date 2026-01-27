// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.exception;

/**
 * Exception related to the publishing of certificates and CRLs.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CertPublisherException extends Exception {

  public CertPublisherException(String message) {
    super(message);
  }

  public CertPublisherException(String message, Throwable cause) {
    super(message, cause);
  }

}
