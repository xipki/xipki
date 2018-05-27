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

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.server.mgmt.api.CaEntry;
import org.xipki.ca.server.mgmt.shell.CaAction;
import org.xipki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.common.util.IoUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.IllegalCmdParamException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class UnRevRmCertAction extends CaAction {

  @Option(name = "--ca", required = true, description = "CA name")
  @Completion(CaNameCompleter.class)
  protected String caName;

  @Option(name = "--cert", aliases = "-c",
      description = "certificate file\n(either cert or serial must be specified)")
  @Completion(FileCompleter.class)
  protected String certFile;

  @Option(name = "--serial", aliases = "-s",
      description = "serial number\n(either cert or serial must be specified)")
  private String serialNumberS;

  protected BigInteger getSerialNumber()
      throws CmdFailure, IllegalCmdParamException, CertificateException, IOException {
    CaEntry ca = caManager.getCa(caName);
    if (ca == null) {
      throw new CmdFailure("CA " + caName + " not available");
    }

    BigInteger serialNumber;
    if (serialNumberS != null) {
      serialNumber = toBigInt(serialNumberS);
    } else if (certFile != null) {
      X509Certificate caCert = ca.getCert();
      X509Certificate cert = X509Util.parseCert(IoUtil.read(certFile));
      if (!X509Util.issues(caCert, cert)) {
        throw new CmdFailure("certificate '" + certFile + "' is not issued by CA " + caName);
      }
      serialNumber = cert.getSerialNumber();
    } else {
      throw new IllegalCmdParamException("neither serialNumber nor certFile is specified");
    }

    return serialNumber;
  }

}
