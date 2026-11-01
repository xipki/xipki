// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client;

import org.xipki.pkix.exception.PkixException;

/**
 * CMP Client Exception type.
 *
 * @author Lijun Liao (xipki)
 */
public class CmpClientException extends PkixException {

  public CmpClientException(String message) {
    super(message);
  }

  public CmpClientException(String message, Throwable cause) {
    super(message, cause);
  }

}
