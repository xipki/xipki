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

package org.xipki.ca.server.mgmt.shell;

import java.io.File;
import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.x509.X509CaEntry;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "gen-rca",
        description = "generate selfsigned CA")
@Service
public class CaGenRcaCmd extends CaAddOrGenAction {

    @Option(name = "--csr",
            required = true,
            description = "CSR of the Root CA\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String csrFile;

    @Option(name = "--profile",
            required = true,
            description = "profile of the Root CA\n"
                    + "(required)")
    private String rcaProfile;

    @Option(name = "--serial",
            description = "profile of the Root CA")
    private String serialS;

    @Option(name = "--out", aliases = "-o",
            description = "where to save the generated CA certificate")
    @Completion(FilePathCompleter.class)
    private String rcaCertOutFile;

    @Override
    protected Object execute0() throws Exception {
        X509CaEntry caEntry = getCaEntry();
        byte[] csr = IoUtil.read(csrFile);
        BigInteger serialNumber = null;
        if (serialS != null) {
            serialNumber = toBigInt(serialS);
        }

        X509Certificate rcaCert = caManager.generateRootCa(caEntry, rcaProfile, csr, serialNumber);
        if (rcaCertOutFile != null) {
            saveVerbose("saved root certificate to file", new File(rcaCertOutFile),
                    rcaCert.getEncoded());
        }
        println("generated root CA " + caEntry.ident().name());
        return null;
    }

}
