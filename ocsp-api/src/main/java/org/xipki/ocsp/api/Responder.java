// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.api;

/**
 * Responder interface.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public interface Responder {

  int getMaxRequestSize();

  boolean supportsHttpGet();

  Long getCacheMaxAge();
}
