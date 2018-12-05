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

package org.xipki.security.shell.pkcs12;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "export-cert-p12",
    description = "export certificate from PKCS#12 keystore")
@Service
public class P12CertExportAction extends P12SecurityAction {

  @Option(name = "--outform", description = "output format of the certificate")
  @Completion(Completers.DerPemCompleter.class)
  protected String outform = "der";

  @Option(name = "--out", aliases = "-o", required = true,
      description = "where to save the certificate")
  @Completion(FileCompleter.class)
  private String outFile;

  @Override
  protected Object execute0() throws Exception {
    KeyStore ks = getKeyStore();

    String keyname = null;
    Enumeration<String> aliases = ks.aliases();
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      if (ks.isKeyEntry(alias)) {
        keyname = alias;
        break;
      }
    }

    if (keyname == null) {
      throw new CmdFailure("could not find private key");
    }

    X509Certificate cert = (X509Certificate) ks.getCertificate(keyname);
    saveVerbose("saved certificate to file", outFile, encodeCert(cert.getEncoded(), outform));

    return null;
  }

}
