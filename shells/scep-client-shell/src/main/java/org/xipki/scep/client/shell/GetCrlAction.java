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

package org.xipki.scep.client.shell;

import java.io.File;
import java.security.cert.X509CRL;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.scep.client.ScepClient;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "scep-getcrl", description = "download CRL")
@Service
public class GetCrlAction extends ClientAction {

  @Option(name = "--cert", aliases = "-c", required = true,
      description = "DER encoded certificate file")
  @Completion(FileCompleter.class)
  private String certFile;

  @Option(name = "--out", aliases = "-o", required = true,
      description = "where to save the DER encoded CRL")
  @Completion(FileCompleter.class)
  private String outputFile;

  @Override
  protected Object execute0() throws Exception {
    Certificate cert = X509Util.parseBcCert(new File(certFile));
    ScepClient client = getScepClient();
    X509CRL crl = client.scepGetCrl(getIdentityKey(), getIdentityCert(),
        cert.getIssuer(), cert.getSerialNumber().getPositiveValue());
    if (crl == null) {
      throw new CmdFailure("received no CRL from server");
    }

    saveVerbose("saved CRL to file", new File(outputFile), crl.getEncoded());
    return null;
  }

}
