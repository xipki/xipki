// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

/**
 * CA System Status enumeration.
 * @author Lijun Liao (xipki)
 */

public enum CaSystemStatus {

  STARTED_AS_MASTER,
  STARTED_AS_SLAVE,
  NOT_INITED,
  INITIALIZING,
  LOCK_FAILED,
  ERROR

}
