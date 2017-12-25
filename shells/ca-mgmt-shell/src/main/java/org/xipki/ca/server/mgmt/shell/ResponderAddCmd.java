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

import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.console.karaf.completer.SignerTypeCompleter;
import org.xipki.password.PasswordResolver;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "responder-add",
        description = "add responder")
@Service
public class ResponderAddCmd extends CaAction {

    @Option(name = "--name", aliases = "-n",
            required = true,
            description = "responder name\n"
                    + "(required)")
    private String name;

    @Option(name = "--signer-type",
            required = true,
            description = "type of the responder signer\n"
                    + "(required)")
    @Completion(SignerTypeCompleter.class)
    private String signerType;

    @Option(name = "--signer-conf",
            required = true,
            description = "conf of the responder signer")
    private String signerConf;

    @Option(name = "--cert",
            description = "responder certificate file")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Reference
    private PasswordResolver passwordResolver;

    @Override
    protected Object execute0() throws Exception {
        String base64Cert = null;
        X509Certificate signerCert = null;
        if (certFile != null) {
            signerCert = X509Util.parseCert(certFile);
            base64Cert = IoUtil.base64Encode(signerCert.getEncoded(), false);
        }

        if ("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType)) {
            signerConf = ShellUtil.canonicalizeSignerConf(signerType, signerConf, passwordResolver,
                    securityFactory);
        }
        CmpResponderEntry entry = new CmpResponderEntry(name, signerType, signerConf, base64Cert);

        boolean bo = caManager.addResponder(entry);
        output(bo, "added", "could not add", "CMP responder " + name);
        return null;
    }

}
