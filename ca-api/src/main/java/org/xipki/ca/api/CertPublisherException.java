// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api;

/**
 * Cert Publisher Exception type.
 *
 * @author Lijun Liao (xipki)
 */
public class CertPublisherException extends Exception {

  public CertPublisherException(String message) {
    super(message);
  }

  public CertPublisherException(String message, Throwable cause) {
    super(message, cause);
  }

}
