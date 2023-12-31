// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.publisher;

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
