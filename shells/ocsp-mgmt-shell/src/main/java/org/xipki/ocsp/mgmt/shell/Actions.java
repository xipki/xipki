/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ocsp.mgmt.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ocsp.mgmt.api.OcspManager;
import org.xipki.ocsp.mgmt.api.OcspMgmtException;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.XiAction;

/**
 * TODO.
 * @author Lijun Liao
 */

public class Actions {

  public abstract static class OcspAction extends XiAction {

    @Reference
    protected OcspManager ocspManager;

  }

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

      StringBuilder sb = new StringBuilder("restarted OCSP server\n");
      print(sb.toString());
      return null;
    } // method execute0

  }

  @Command(scope = "ocsp", name = "refresh-token", description = "refresh token for signers")
  @Service
  public static class RefreshTokenAction extends OcspAction {

    @Option(name = "--type", required = true, description = "type of the signer")
    @Completion(Completers.SignerTypeCompleter.class)
    protected String type;

    @Override
    protected Object execute0() throws Exception {
      ocspManager.refreshTokenForSignerType(type);
      println("refreshed token for signer type " + type);
      return null;
    } // method execute0

  }

}
