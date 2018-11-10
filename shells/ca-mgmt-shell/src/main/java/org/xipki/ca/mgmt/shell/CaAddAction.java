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

package org.xipki.ca.mgmt.shell;

import java.io.File;
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.mgmt.api.CaEntry;
import org.xipki.ca.mgmt.api.CaMgmtException;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "ca-add", description = "add CA")
@Service
public class CaAddAction extends CaAddOrGenAction {

  @Option(name = "--cert", description = "DER encded CA certificate file")
  @Completion(FileCompleter.class)
  private String certFile;

  @Override
  protected Object execute0() throws Exception {
    CaEntry caEntry = getCaEntry();
    if (certFile != null) {
      X509Certificate caCert = X509Util.parseCert(new File(certFile));
      caEntry.setCert(caCert);
    }

    String msg = "CA " + caEntry.getIdent().getName();
    try {
      caManager.addCa(caEntry);
      println("added " + msg);
      return null;
    } catch (CaMgmtException ex) {
      throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
    }
  }

}
