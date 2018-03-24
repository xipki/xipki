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

package org.xipki.ca.server.mgmt.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.api.NameId;
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.completer.FilePathCompleter;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "requestor-add",
    description = "add requestor")
@Service
public class RequestorAddCmd extends CaAction {

  @Option(name = "--name", aliases = "-n", required = true,
      description = "requestor name\n(required)")
  private String name;

  @Option(name = "--cert", required = true,
      description = "requestor certificate file\n(required)")
  @Completion(FilePathCompleter.class)
  private String certFile;

  @Override
  protected Object execute0() throws Exception {
    String base64Cert = IoUtil.base64Encode(IoUtil.read(certFile), false);
    CmpRequestorEntry entry = new CmpRequestorEntry(new NameId(null, name), base64Cert);

    String msg = "CMP requestor " + name;
    if (entry.getCert() == null) {
      throw new CmdFailure("could not add " + msg + ", error: could not get requestor certificate");
    }

    try {
      caManager.addRequestor(entry);
      println("added " + msg);
      return null;
    } catch (CaMgmtException ex) {
      throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
    }
  }

}
