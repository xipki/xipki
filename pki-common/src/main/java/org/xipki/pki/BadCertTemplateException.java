// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pki;

/**
 * Exception indicates bad certificate template.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class BadCertTemplateException extends Exception {

  public BadCertTemplateException(String message) {
    super(message);
  }

  public BadCertTemplateException(String message, Throwable cause) {
    super(message, cause);
  }

}
