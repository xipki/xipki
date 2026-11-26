// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import java.io.IOException;
import org.xipki.mgmt.web.ca.CaDomain.CaMgmtException;
import org.xipki.mgmt.web.ca.CaManager;

/**
 * Coordinates a remote CA deletion with local authorization cleanup.
 *
 * @author palos
 */
final class CaRemoval {
  static void remove(CaManager manager, String name, Runnable cleanup) throws CaMgmtException {
    try {
      manager.removeCa(name);
    } catch (CaMgmtException ex) {
      if (!transportFailure(ex)) {
        throw ex;
      }
      try {
        if (manager.getCaNames().contains(name)) {
          throw ex;
        }
      } catch (CaMgmtException lookupFailure) {
        if (lookupFailure != ex) {
          ex.addSuppressed(lookupFailure);
        }
        throw ex;
      }
    }
    cleanup.run();
  }

  private static boolean transportFailure(Throwable failure) {
    for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
      if (cause instanceof IOException) {
        return true;
      }
    }
    return false;
  }

  private CaRemoval() {}
}
