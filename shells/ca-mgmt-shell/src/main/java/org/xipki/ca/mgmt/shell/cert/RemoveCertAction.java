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

package org.xipki.ca.mgmt.shell.cert;

import java.math.BigInteger;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.mgmt.api.CaMgmtException;
import org.xipki.shell.CmdFailure;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "rm-cert", description = "remove certificate")
@Service
public class RemoveCertAction extends UnRevRmCertAction {

  @Option(name = "--force", aliases = "-f", description = "without prompt")
  private Boolean force = Boolean.FALSE;

  @Override
  protected Object execute0() throws Exception {
    BigInteger serialNo = getSerialNumber();
    String msg = "certificate (serial number = 0x" + serialNo.toString(16) + ")";
    if (force || confirm("Do you want to remove " + msg, 3)) {
      try {
        caManager.removeCertificate(caName, serialNo);
        println("removed " + msg);
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
      }
    }
    return null;
  }

}
