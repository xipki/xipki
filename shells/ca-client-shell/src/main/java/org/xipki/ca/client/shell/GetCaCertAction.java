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
import java.security.cert.Certificate;
import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.client.shell.completer.CaNameCompleter;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.IllegalCmdParamException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "cmp-cacert", description = "get CA certificate")
@Service
public class GetCaCertAction extends ClientAction {

  @Option(name = "--ca", description = "CA name\n(required if multiple CAs are configured)")
  @Completion(CaNameCompleter.class)
  protected String caName;

  @Option(name = "--out", aliases = "-o", required = true,
      description = "where to save the CA certificate")
  @Completion(FileCompleter.class)
  protected String outFile;

  @Override
  protected Object execute0() throws Exception {
    if (caName != null) {
      caName = caName.toLowerCase();
    }

    Set<String> caNames = caClient.getCaNames();
    if (isEmpty(caNames)) {
      throw new CmdFailure("no CA is configured");
    }

    if (caName != null && !caNames.contains(caName)) {
      throw new IllegalCmdParamException("CA " + caName
          + " is not within the configured CAs " + caNames);
    }

    if (caName == null) {
      if (caNames.size() == 1) {
        caName = caNames.iterator().next();
      } else {
        throw new IllegalCmdParamException("no CA is specified, one of " + caNames
            + " is required");
      }
    }

    Certificate caCert;
    try {
      caCert = caClient.getCaCert(caName);
    } catch (Exception ex) {
      throw new CmdFailure("Error while retrieving CA certificate: " + ex.getMessage());
    }

    if (caCert == null) {
      throw new CmdFailure("received no CA certificate");
    }

    saveVerbose("saved CA certificate to file", new File(outFile), caCert.getEncoded());
    return null;
  } // method execute0

}
