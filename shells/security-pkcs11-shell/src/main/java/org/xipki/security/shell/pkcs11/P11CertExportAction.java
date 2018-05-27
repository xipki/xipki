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

package org.xipki.security.shell.pkcs11;

import java.io.File;
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.shell.CmdFailure;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "export-cert-p11",
    description = "export certificate from PKCS#11 device")
@Service
public class P11CertExportAction extends P11SecurityAction {

  @Option(name = "--id",
      description = "id of the private key in the PKCS#11 device\n"
          + "either keyId or keyLabel must be specified")
  protected String id;

  @Option(name = "--label",
      description = "label of the private key in the PKCS#11 device\n"
          + "either keyId or keyLabel must be specified")
  protected String label;

  @Option(name = "--out", aliases = "-o", required = true,
      description = "where to save the certificate")
  @Completion(FileCompleter.class)
  private String outFile;

  @Override
  protected Object execute0() throws Exception {
    P11Slot slot = getSlot();
    P11ObjectIdentifier objIdentifier = getObjectIdentifier(id, label);
    X509Certificate cert = slot.exportCert(objIdentifier);
    if (cert == null) {
      throw new CmdFailure("could not export certificate " + objIdentifier);
    }
    saveVerbose("saved certificate to file", new File(outFile), cert.getEncoded());
    return null;
  }

}
