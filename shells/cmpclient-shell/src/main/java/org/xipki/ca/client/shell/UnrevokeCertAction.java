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

package org.xipki.ca.client.shell;

import java.io.File;
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.cmpclient.CertIdOrError;
import org.xipki.security.cmp.PkiStatusInfo;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.ReqRespDebug;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "cmp-unrevoke", description = "unrevoke certificate")
@Service
public class UnrevokeCertAction extends UnRevRemoveCertAction {

  @Override
  protected Object execute0() throws Exception {
    if (!(certFile == null ^ getSerialNumber() == null)) {
      throw new IllegalCmdParamException("exactly one of cert and serial must be specified");
    }

    ReqRespDebug debug = getReqRespDebug();
    CertIdOrError certIdOrError;
    try {
      if (certFile != null) {
        X509Certificate cert = X509Util.parseCert(new File(certFile));
        certIdOrError = client.unrevokeCert(caName, cert, debug);
      } else {
        certIdOrError = client.unrevokeCert(caName, getSerialNumber(), debug);
      }
    } finally {
      saveRequestResponse(debug);
    }

    if (certIdOrError.getError() != null) {
      PkiStatusInfo error = certIdOrError.getError();
      throw new CmdFailure("releasing revocation failed: " + error);
    } else {
      println("unrevoked certificate");
    }
    return null;
  } // method execute0

}
