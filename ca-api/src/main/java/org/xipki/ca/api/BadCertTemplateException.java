// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api;

/**
 * Bad Cert Template Exception type.
 *
 * @author Lijun Liao (xipki)
 */
public class BadCertTemplateException extends Exception {

  public BadCertTemplateException(String message) {
    super(message);
  }

  public BadCertTemplateException(String message, Throwable cause) {
    super(message, cause);
  }

}
