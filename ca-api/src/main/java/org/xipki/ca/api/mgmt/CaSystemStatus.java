// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

/**
 * CA system status enum.
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public enum CaSystemStatus {

  STARTED_AS_MASTER,
  STARTED_AS_SLAVE,
  NOT_INITED,
  INITIALIZING,
  LOCK_FAILED,
  ERROR

}
