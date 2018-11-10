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

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.mgmt.api.CaEntry;
import org.xipki.shell.completer.DerPemCompleter;
import org.xipki.util.IoUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "gen-rootca", description = "generate selfsigned CA")
@Service
public class CaGenRcaAction extends CaAddOrGenAction {

  @Option(name = "--csr", required = true, description = "CSR of the Root CA")
  @Completion(FileCompleter.class)
  private String csrFile;

  @Option(name = "--profile", required = true, description = "profile of the Root CA")
  private String rootcaProfile;

  @Option(name = "--serial", description = "profile of the Root CA")
  private String serialS;

  @Option(name = "--outform", description = "output format of the certificate")
  @Completion(DerPemCompleter.class)
  protected String outform = "der";

  @Option(name = "--out", aliases = "-o",
      description = "where to save the generated CA certificate")
  @Completion(FileCompleter.class)
  private String rootcaCertOutFile;

  @Override
  protected Object execute0() throws Exception {
    CaEntry caEntry = getCaEntry();
    byte[] csr = IoUtil.read(csrFile);
    BigInteger serialNumber = null;
    if (serialS != null) {
      serialNumber = toBigInt(serialS);
    }

    X509Certificate rootcaCert = caManager.generateRootCa(caEntry, rootcaProfile, csr,
        serialNumber);
    if (rootcaCertOutFile != null) {
      saveVerbose("saved root certificate to file", rootcaCertOutFile,
          encodeCert(rootcaCert.getEncoded(), outform));
    }
    println("generated root CA " + caEntry.getIdent().getName());
    return null;
  }

}
