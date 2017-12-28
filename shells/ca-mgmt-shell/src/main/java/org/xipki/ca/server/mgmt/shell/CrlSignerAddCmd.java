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

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.x509.X509CrlSignerEntry;
import org.xipki.ca.server.mgmt.shell.completer.CrlSignerNameCompleter;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.password.PasswordResolver;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "crlsigner-add",
        description = "add CRL signer")
@Service
public class CrlSignerAddCmd extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true,
            description = "CRL signer name\n(required)")
    private String name;

    @Option(name = "--signer-type", required = true,
            description = "CRL signer type, use 'CA' to sign the CRL by the CA itself\n(required)")
    @Completion(CrlSignerNameCompleter.class)
    private String signerType;

    @Option(name = "--signer-conf",
            description = "CRL signer configuration")
    private String signerConf;

    @Option(name = "--cert",
            description = "CRL signer's certificate file")
    @Completion(FilePathCompleter.class)
    private String signerCertFile;

    @Option(name = "--control", required = true,
            description = "CRL control\n(required)")
    private String crlControl;

    @Reference
    private PasswordResolver passwordResolver;

    @Override
    protected Object execute0() throws Exception {
        String base64Cert = null;
        if (!"CA".equalsIgnoreCase(signerType)) {
            if (signerCertFile != null) {
                byte[] encodedCert = IoUtil.read(signerCertFile);
                base64Cert = IoUtil.base64Encode(encodedCert, false);
                X509Util.parseCert(encodedCert);
            }

            if (signerConf != null) {
                if ("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType)) {
                    signerConf = ShellUtil.canonicalizeSignerConf(signerType,
                            signerConf, passwordResolver, securityFactory);
                }
            }
        }

        X509CrlSignerEntry entry = new X509CrlSignerEntry(name, signerType, signerConf, base64Cert,
                crlControl);
        boolean bo = caManager.addCrlSigner(entry);
        output(bo, "added", "could not add", "CRL signer " + name);
        return null;
    }

}
