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

package org.xipki.scep.jscep.client.shell;

import java.io.File;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.jscep.client.Client;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-jscep", name = "getcrl",
        description = "download CRL")
@Service
public class GetCrlCmd extends ClientCommandSupport {

    @Option(name = "--cert", aliases = "-c",
            required = true,
            description = "certificate\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Option(name = "--out", aliases = "-o",
            required = true,
            description = "where to save the certificate\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String outputFile;

    @Override
    protected Object execute0() throws Exception {
        X509Certificate cert = X509Util.parseCert(new File(certFile));
        Client client = getScepClient();
        X509CRL crl = client.getRevocationList(getIdentityCert(), getIdentityKey(),
                cert.getIssuerX500Principal(), cert.getSerialNumber());
        if (crl == null) {
            throw new CmdFailure("received no CRL from server");
        }

        saveVerbose("saved CRL to file", new File(outputFile), crl.getEncoded());
        return null;
    }

}
