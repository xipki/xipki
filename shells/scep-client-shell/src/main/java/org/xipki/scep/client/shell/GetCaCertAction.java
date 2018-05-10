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
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.XiAction;
import org.xipki.scep.client.CaCertValidator;
import org.xipki.scep.client.CaIdentifier;
import org.xipki.scep.client.ScepClient;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "scep-cacert",
    description = "get CA certificate")
@Service
public class GetCaCertAction extends XiAction {

  @Option(name = "--url", required = true,
      description = "URL of the SCEP server\n(required)")
  private String url;

  @Option(name = "--ca-id",
      description = "CA identifier")
  private String caId;

  @Option(name = "--out", aliases = "-o", required = true,
      description = "where to save the CA certificate\n(required)")
  @Completion(FileCompleter.class)
  protected String outFile;

  @Override
  protected Object execute0() throws Exception {
    CaIdentifier tmpCaId = new CaIdentifier(url, caId);
    CaCertValidator caCertValidator = new CaCertValidator() {
      @Override
      public boolean isTrusted(X509Certificate cert) {
        return true;
      }
    };

    ScepClient client = new ScepClient(tmpCaId, caCertValidator);
    client.init();
    X509Certificate caCert = client.getCaCert();
    if (caCert == null) {
      throw new CmdFailure("received no CA certficate from server");
    }

    saveVerbose("saved certificate to file", new File(outFile), caCert.getEncoded());
    return null;
  }

}
