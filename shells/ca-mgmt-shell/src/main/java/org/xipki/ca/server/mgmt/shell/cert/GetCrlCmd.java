/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.ca.server.mgmt.shell.cert;

import java.io.File;
import java.math.BigInteger;
import java.security.cert.X509CRL;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.ca.server.mgmt.api.CaEntry;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "getcrl",
        description = "download CRL")
@Service
public class GetCrlCmd extends CrlCommandSupport {

    @Option(name = "--with-basecrl",
            description = "whether to retrieve the baseCRL if the current CRL is a delta CRL")
    private Boolean withBaseCrl = Boolean.FALSE;

    @Option(name = "--basecrl-out",
            description = "where to save the baseCRL\n"
                    + "(defaults to <out>-baseCRL)")
    @Completion(FilePathCompleter.class)
    private String baseCrlOut;

    @Override
    protected X509CRL retrieveCrl() throws Exception {
        return caManager.getCurrentCrl(caName);
    }

    @Override
    protected Object execute0() throws Exception {
        CaEntry ca = caManager.getCa(caName);
        if (ca == null) {
            throw new CmdFailure("CA " + caName + " not available");
        }

        X509CRL crl = null;
        try {
            crl = retrieveCrl();
        } catch (Exception ex) {
            throw new CmdFailure("received no CRL from server: " + ex.getMessage());
        }

        if (crl == null) {
            throw new CmdFailure("received no CRL from server");
        }

        saveVerbose("saved CRL to file", new File(outFile), crl.getEncoded());

        if (withBaseCrl.booleanValue()) {
            byte[] octetString = crl.getExtensionValue(Extension.deltaCRLIndicator.getId());
            if (octetString != null) {
                if (baseCrlOut == null) {
                    baseCrlOut = outFile + "-baseCRL";
                }

                byte[] extnValue = DEROctetString.getInstance(octetString).getOctets();
                BigInteger baseCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();

                try {
                    crl = caManager.getCrl(caName, baseCrlNumber);
                } catch (Exception ex) {
                    throw new CmdFailure("received no baseCRL from server: " + ex.getMessage());
                }

                if (crl == null) {
                    throw new CmdFailure("received no baseCRL from server");
                } else {
                    saveVerbose("saved baseCRL to file", new File(baseCrlOut), crl.getEncoded());
                }
            }
        }

        return null;
    } // method execute0

}
