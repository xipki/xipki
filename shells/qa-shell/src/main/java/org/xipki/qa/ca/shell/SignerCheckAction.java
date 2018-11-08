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

package org.xipki.qa.ca.shell;

import java.util.Arrays;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.CaManager;
import org.xipki.ca.server.mgmt.api.SignerEntry;
import org.xipki.ca.server.mgmt.shell.SignerUpdateAction;
import org.xipki.shell.CmdFailure;
import org.xipki.util.Base64;
import org.xipki.util.IoUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "caqa", name = "signer-check", description = "check information of signer (QA)")
@Service
public class SignerCheckAction extends SignerUpdateAction {

  @Override
  protected Object execute0() throws Exception {
    println("checking signer " + name);

    SignerEntry cr = caManager.getSigner(name);
    if (cr == null) {
      throw new CmdFailure("signer named '" + name + "' is not configured");
    }

    if (CaManager.NULL.equalsIgnoreCase(certFile)) {
      if (cr.getBase64Cert() != null) {
        throw new CmdFailure("Cert: is configured but expected is none");
      }
    } else if (certFile != null) {
      byte[] ex = IoUtil.read(certFile);
      if (cr.getBase64Cert() == null) {
        throw new CmdFailure("Cert: is not configured explicitly as expected");
      }
      if (!Arrays.equals(ex, Base64.decode(cr.getBase64Cert()))) {
        throw new CmdFailure("Cert: the expected one and the actual one differ");
      }
    }

    String signerConf = getSignerConf();
    if (signerConf != null) {
      MgmtQaShellUtil.assertEquals("conf", signerConf, cr.getConf());
    }

    println(" checked signer " + name);
    return null;
  }

}
