// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

/**
 * Exception related to Certprofile.
 *
 * @author Lijun Liao
 * @since 2.0.0
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
