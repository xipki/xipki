// License Apache License 2.0

package org.xipki.mgmt.web.service;

import org.xipki.mgmt.web.ca.CaDomain.CaMgmtException;
import org.xipki.mgmt.web.ca.CaDomain.CaSystemStatus;
import org.xipki.mgmt.web.ca.CaManager;
import org.xipki.mgmt.web.core.ApiException;

/**
 * Service layer exposing the stable Console management interface to controllers.
 *
 * @author palos
 */
public class CaManagementService {

  private final CaManager caMgmtClient;

  /** Creates the service around a management implementation or test double. */
  public CaManagementService(CaManager caMgmtClient) {
    this.caMgmtClient = caMgmtClient;
  }

  public CaManager getCaManager() {
    return caMgmtClient;
  }

  public boolean isReady() {
    try {
      return caMgmtClient.getCaSystemStatus() == CaSystemStatus.STARTED_AS_MASTER
          && caMgmtClient.getCaNames() != null;
    } catch (CaMgmtException ex) {
      return false;
    }
  }

  /** Configured/inactive CAs are not present in XiPKI's runtime instance map. */
  public void requireStarted(String name) throws CaMgmtException {
    if (!caMgmtClient.getSuccessfulCaNames().contains(name)) {
      throw new ApiException(409, "CA is not running; refresh the CA list and select a running CA");
    }
  }
}
