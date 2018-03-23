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
import java.security.cert.X509CRL;
import java.util.Set;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.xipki.ca.client.api.CaClientException;
import org.xipki.ca.client.api.PkiErrorException;
import org.xipki.ca.client.shell.completer.CaNameCompleter;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.completer.FilePathCompleter;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class CrlAction extends ClientAction {

  @Option(name = "--ca",
      description = "CA name\n(required if multiple CAs are configured)")
  @Completion(CaNameCompleter.class)
  protected String caName;

  @Option(name = "--out", aliases = "-o", required = true,
      description = "where to save the CRL\n(required)")
  @Completion(FilePathCompleter.class)
  protected String outFile;

  protected abstract X509CRL retrieveCrl() throws CaClientException, PkiErrorException;

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

    X509CRL crl = null;
    try {
      crl = retrieveCrl();
    } catch (PkiErrorException ex) {
      throw new CmdFailure("received no CRL from server: " + ex.getMessage());
    }

    if (crl == null) {
      throw new CmdFailure("received no CRL from server");
    }

    saveVerbose("saved CRL to file", new File(outFile), crl.getEncoded());
    return null;
  } // method execute0

}
