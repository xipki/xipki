// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.mgmt.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ocsp.api.mgmt.OcspManager;
import org.xipki.ocsp.api.mgmt.OcspMgmtException;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.XiAction;

/**
 * OCSP server management actions.
 *
 * @author Lijun Liao (xipki)
 */

public class Actions {

  public abstract static class OcspAction extends XiAction {

    @Reference
    protected OcspManager ocspManager;

  } // class OcspAction

  @Command(scope = "ocsp", name = "restart-server", description = "restart OCSP server")
  @Service
  public static class OcspSystemRestartAction extends OcspAction {

    @Override
    protected Object execute0() throws Exception {
      try {
        ocspManager.restartOcspServer();
      } catch (OcspMgmtException ex) {
        throw new CmdFailure("could not restart OCSP server, error: " + ex.getMessage(), ex);
      }

      print("restarted OCSP server\n");
      return null;
    } // method execute0

  } // class OcspSystemRestartAction

}
