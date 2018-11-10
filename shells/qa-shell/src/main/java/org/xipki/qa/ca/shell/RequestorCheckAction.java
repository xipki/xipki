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
import org.xipki.ca.mgmt.api.RequestorEntry;
import org.xipki.ca.mgmt.shell.RequestorUpdateAction;
import org.xipki.shell.CmdFailure;
import org.xipki.util.Base64;
import org.xipki.util.IoUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "caqa", name = "requestor-check",
    description = "check information of requestors (QA)")
@Service
public class RequestorCheckAction extends RequestorUpdateAction {

  @Override
  protected Object execute0() throws Exception {
    println("checking requestor " + name);

    RequestorEntry cr = caManager.getRequestor(name);
    if (cr == null) {
      throw new CmdFailure("requestor named '" + name + "' is not configured");
    }

    if (certFile != null) {
      byte[] ex = IoUtil.read(certFile);
      String expType = RequestorEntry.TYPE_CERT;
      if (!cr.getType().equals(expType)) {
        throw new CmdFailure("Requestor type is not " + expType);
      }

      String conf = cr.getConf();
      if (conf == null) {
        throw new CmdFailure("Cert: is not configured explicitly as expected");
      }

      if (!MgmtQaShellUtil.certEquals(ex, Base64.decode(conf))) {
        throw new CmdFailure("Cert: the expected one and the actual one differ");
      }
    } else {
      String expType = RequestorEntry.TYPE_PBM;
      if (!cr.getType().equals(expType)) {
        throw new CmdFailure("Requestor type is not " + expType);
      }

      char[] ex = password.toCharArray();
      char[] is = securityFactory.getPasswordResolver().resolvePassword(cr.getConf());
      if (Arrays.equals(ex, is)) {
        throw new CmdFailure("PBM: the expected one and the actual one differ");
      }
    }

    println(" checked requestor " + name);
    return null;
  }

}
