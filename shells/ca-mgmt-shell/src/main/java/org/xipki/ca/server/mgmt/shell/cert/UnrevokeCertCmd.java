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

package org.xipki.ca.server.mgmt.shell.cert;

import java.math.BigInteger;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.console.karaf.CmdFailure;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "unrevoke-cert",
    description = "unrevoke certificate")
@Service
public class UnrevokeCertCmd extends UnRevRmCertAction {

  @Override
  protected Object execute0() throws Exception {
    BigInteger serialNo = getSerialNumber();
    String msg = "certificate (serial number = 0x" + serialNo.toString(16) + ")";
    try {
      caManager.unrevokeCertificate(caName, serialNo);
      println("unrevoked " + msg);
      return null;
    } catch (CaMgmtException ex) {
      throw new CmdFailure("could not unrevoke " + msg + ", error: " + ex.getMessage(), ex);
    }
  }

}
