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

import java.io.ByteArrayInputStream;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.CaManager;
import org.xipki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.ca.server.mgmt.shell.completer.ResponderNameCompleter;
import org.xipki.common.util.Base64;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.console.karaf.completer.SignerTypeCompleter;
import org.xipki.password.PasswordResolver;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "responder-up",
        description = "update responder")
@Service
public class ResponderUpdateCmd extends CaAction {

    @Reference
    protected PasswordResolver passwordResolver;

    @Option(name = "--name", aliases = "-n",
            required = true,
            description = "responder name\n"
                    + "(required)")
    @Completion(ResponderNameCompleter.class)
    protected String name;

    @Option(name = "--signer-type",
            description = "type of the responder signer")
    @Completion(SignerTypeCompleter.class)
    protected String signerType;

    @Option(name = "--cert",
            description = "requestor certificate file or 'NULL'")
    @Completion(FilePathCompleter.class)
    protected String certFile;

    @Option(name = "--signer-conf",
            description = "conf of the responder signer or 'NULL'")
    private String signerConf;

    protected String getSignerConf() throws Exception {
        if (signerConf == null) {
            return signerConf;
        }
        String tmpSignerType = signerType;
        if (tmpSignerType == null) {
            CmpResponderEntry entry = caManager.getResponder(name);
            if (entry == null) {
                throw new IllegalCmdParamException("please specify the signerType");
            }
            tmpSignerType = entry.type();
        }

        return ShellUtil.canonicalizeSignerConf(tmpSignerType, signerConf, passwordResolver,
                securityFactory);
    }

    @Override
    protected Object execute0() throws Exception {
        String cert = null;
        if (CaManager.NULL.equalsIgnoreCase(certFile)) {
            cert = CaManager.NULL;
        } else if (certFile != null) {
            byte[] certBytes = IoUtil.read(certFile);
            X509Util.parseCert(new ByteArrayInputStream(certBytes));
            cert = Base64.encodeToString(certBytes);
        }

        boolean bo = caManager.changeResponder(name, signerType, getSignerConf(), cert);
        output(bo, "updated", "could not update", "CMP responder " + name);
        return null;
    }

}
