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

import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.api.NameId;
import org.xipki.ca.mgmt.api.CaMgmtException;
import org.xipki.ca.mgmt.api.RequestorEntry;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.util.Base64;
import org.xipki.util.IoUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "requestor-add", description = "add requestor")
@Service
public class RequestorAddAction extends CaAction {

  @Option(name = "--name", aliases = "-n", required = true, description = "requestor name")
  private String name;

  @Option(name = "--cert", description = "requestor certificate file\n"
      + "(exactly one of cert and password must be specified).")
  @Completion(FileCompleter.class)
  private String certFile;

  @Option(name = "--password", description = "Passord for PBM (Password based MAC)")
  private String password;

  @Override
  protected Object execute0() throws Exception {
    if (!(certFile == null ^ password == null)) {
      throw new CmdFailure("exactly one of cert and password must be specified");
    }

    RequestorEntry entry;
    if (certFile != null) {
      X509Certificate cert = X509Util.parseCert(IoUtil.read(certFile));
      entry = new RequestorEntry(new NameId(null, name), RequestorEntry.TYPE_CERT,
          Base64.encodeToString(cert.getEncoded()));
    } else {
      entry = new RequestorEntry(new NameId(null, name), RequestorEntry.TYPE_PBM, password);
      String keyId = HashAlgo.SHA1.hexHash(entry.getIdent().getName().getBytes("UTF-8"));
      println("The key ID is " + keyId);
    }

    String msg = "CMP requestor " + name;

    try {
      caManager.addRequestor(entry);
      println("added " + msg);
      return null;
    } catch (CaMgmtException ex) {
      throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
    }
  }

}
