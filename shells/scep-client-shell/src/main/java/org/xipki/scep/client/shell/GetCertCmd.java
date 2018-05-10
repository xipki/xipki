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
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.scep.client.ScepClient;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "scep-getcert",
    description = "download certificate")
@Service
public class GetCertCmd extends ClientAction {

  @Option(name = "--serial", aliases = "-s", required = true,
      description = "serial number\n(required)")
  private String serialNumber;

  @Option(name = "--out", aliases = "-o", required = true,
      description = "where to save the certificate\n(required)")
  @Completion(FileCompleter.class)
  private String outputFile;

  @Override
  protected Object execute0() throws Exception {
    ScepClient client = getScepClient();
    BigInteger serial = toBigInt(serialNumber);
    X509Certificate caCert = client.getAuthorityCertStore().getCaCert();
    X500Name caSubject = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
    List<X509Certificate> certs = client.scepGetCert(getIdentityKey(), getIdentityCert(),
        caSubject, serial);
    if (certs == null || certs.isEmpty()) {
      throw new CmdFailure("received no certficate from server");
    }

    saveVerbose("saved certificate to file", new File(outputFile), certs.get(0).getEncoded());
    return null;
  }

}
