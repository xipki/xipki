// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client;

import org.xipki.util.exception.PkixException;

/**
 * SCEP Client Exception type.
 *
 * @author Lijun Liao (xipki)
 */
public class ScepClientException extends PkixException {

  public ScepClientException(String message, Throwable cause) {
    super(message, cause);
  }

  public ScepClientException(String message) {
    super(message);
  }

  public ScepClientException(Throwable cause) {
    super(cause.getMessage(), cause);
  }

}
