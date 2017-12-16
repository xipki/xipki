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

import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.api.NameId;
import org.xipki.ca.server.mgmt.api.x509.ScepEntry;
import org.xipki.ca.server.mgmt.shell.completer.ProfileNameAndAllCompleter;
import org.xipki.ca.server.mgmt.shell.completer.ScepNameCompleter;
import org.xipki.common.InvalidConfException;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.console.karaf.completer.SignerTypeCompleter;
import org.xipki.password.PasswordResolver;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "scep-add",
        description = "add SCEP")
@Service
public class ScepAddCmd extends CaCommandSupport {

    @Option(name = "--name",
            required = true,
            description = "name\n"
                    + "(required)")
    private String name;

    @Option(name = "--ca",
            required = true,
            description = "CA name\n"
                    + "(required)")
    @Completion(ScepNameCompleter.class)
    private String caName;

    @Option(name = "--inactive",
            description = "do not activate this SCEP")
    private Boolean inactive = Boolean.FALSE;

    @Option(name = "--resp-type",
            required = true,
            description = "type of the responder\n"
                    + "(required)")
    @Completion(SignerTypeCompleter.class)
    private String responderType;

    @Option(name = "--resp-conf",
            required = true,
            description = "conf of the responder\n"
                    + "(required)")
    private String responderConf;

    @Option(name = "--resp-cert",
            description = "responder certificate file")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Option(name = "--control",
            required = false,
            description = "SCEP control")
    private String scepControl;

    @Option(name = "--profile",
            required = true, multiValued = true,
            description = "profile name or 'ALL' for all profiles\n"
                    + "(required, multi-valued)")
    @Completion(ProfileNameAndAllCompleter.class)
    private Set<String> profiles;

    @Reference
    private PasswordResolver passwordResolver;

    @Override
    protected Object execute0() throws Exception {
        String base64Cert = null;
        if (certFile != null) {
            base64Cert = IoUtil.base64Encode(IoUtil.read(certFile), false);
        }

        if ("PKCS12".equalsIgnoreCase(responderType) || "JKS".equalsIgnoreCase(responderType)) {
            responderConf = ShellUtil.canonicalizeSignerConf(responderType, responderConf,
                    passwordResolver, securityFactory);
        }

        ScepEntry entry = new ScepEntry(name, new NameId(null, caName), !inactive, responderType,
                responderConf, base64Cert, profiles, scepControl);
        if (entry.isFaulty()) {
            throw new InvalidConfException("certificate is invalid");
        }

        boolean bo = caManager.addScep(entry);
        output(bo, "added", "could not add", "SCEP responder " + name);
        return null;
    }

}
