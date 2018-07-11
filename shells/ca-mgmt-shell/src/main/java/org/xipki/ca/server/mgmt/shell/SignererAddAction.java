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

package org.xipki.ca.server.mgmt.shell;

import java.io.File;
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.ca.server.mgmt.api.SignerEntry;
import org.xipki.ca.server.mgmt.shell.completer.SignerTypeCompleter;
import org.xipki.password.PasswordResolver;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.util.IoUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "signer-add", description = "add signer")
@Service
public class SignererAddAction extends CaAction {

  @Option(name = "--name", aliases = "-n", required = true, description = "signer name")
  private String name;

  @Option(name = "--type", required = true, description = "type of the signer")
  @Completion(SignerTypeCompleter.class)
  private String type;

  @Option(name = "--conf", required = true, description = "conf of the signer")
  private String conf;

  @Option(name = "--cert", description = "DER encoded signer certificate file")
  @Completion(FileCompleter.class)
  private String certFile;

  @Reference
  private PasswordResolver passwordResolver;

  @Override
  protected Object execute0() throws Exception {
    String base64Cert = null;
    X509Certificate signerCert = null;
    if (certFile != null) {
      signerCert = X509Util.parseCert(new File(certFile));
      base64Cert = IoUtil.base64Encode(signerCert.getEncoded(), false);
    }

    if ("PKCS12".equalsIgnoreCase(type) || "JKS".equalsIgnoreCase(type)) {
      conf = ShellUtil.canonicalizeSignerConf(type, conf, passwordResolver, securityFactory);
    }
    SignerEntry entry = new SignerEntry(name, type, conf, base64Cert);

    String msg = "signer " + name;
    try {
      caManager.addSigner(entry);
      println("added " + msg);
      return null;
    } catch (CaMgmtException ex) {
      throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
    }
  }

}
