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
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.ca.client.api.CaClientException;
import org.xipki.ca.client.api.PkiErrorException;
import org.xipki.common.RequestResponseDebug;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.IllegalCmdParamException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "cmp-getcrl",
    description = "download CRL")
@Service
public class GetCrlAction extends CrlAction {

  @Option(name = "--with-basecrl",
      description = "whether to retrieve the baseCRL if the current CRL is a delta CRL")
  private Boolean withBaseCrl = Boolean.FALSE;

  @Option(name = "--basecrl-out",
      description = "where to save the baseCRL\n(defaults to <out>-baseCRL)")
  @Completion(FileCompleter.class)
  private String baseCrlOut;

  @Override
  protected X509CRL retrieveCrl() throws CaClientException, PkiErrorException {
    RequestResponseDebug debug = getRequestResponseDebug();
    try {
      return caClient.downloadCrl(caName, debug);
    } finally {
      saveRequestResponse(debug);
    }
  }

  @Override
  protected Object execute0() throws Exception {
    if (caName != null) {
      caName = caName.toLowerCase();
    }

    Set<String> caNames = caClient.getCaNames();
    if (isEmpty(caNames)) {
      throw new IllegalCmdParamException("no CA is configured");
    }

    if (caName != null && !caNames.contains(caName)) {
      throw new IllegalCmdParamException("CA " + caName + " is not within the configured CAs "
          + caNames);
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

    if (!withBaseCrl.booleanValue()) {
      return null;
    }

    byte[] octetString = crl.getExtensionValue(Extension.deltaCRLIndicator.getId());
    if (octetString == null) {
      return null;
    }

    if (baseCrlOut == null) {
      baseCrlOut = outFile + "-baseCRL";
    }

    byte[] extnValue = DEROctetString.getInstance(octetString).getOctets();
    BigInteger baseCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();

    RequestResponseDebug debug = getRequestResponseDebug();
    try {
      crl = caClient.downloadCrl(caName, baseCrlNumber, debug);
    } catch (PkiErrorException ex) {
      throw new CmdFailure("received no baseCRL from server: " + ex.getMessage());
    } finally {
      saveRequestResponse(debug);
    }

    if (crl == null) {
      throw new CmdFailure("received no baseCRL from server");
    }

    saveVerbose("saved baseCRL to file", new File(baseCrlOut), crl.getEncoded());
    return null;
  } // method execute0

}
