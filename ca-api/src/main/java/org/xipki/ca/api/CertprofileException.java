// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api;

/**
 * Certprofile Exception type.
 *
 * @author Lijun Liao (xipki)
 */
public class CertprofileException extends Exception {

  public CertprofileException() {
  }

  public CertprofileException(String message) {
    super(message);
  }

  public CertprofileException(Throwable cause) {
    super(cause);
  }

  public CertprofileException(String message, Throwable cause) {
    super(message, cause);
  }

}
