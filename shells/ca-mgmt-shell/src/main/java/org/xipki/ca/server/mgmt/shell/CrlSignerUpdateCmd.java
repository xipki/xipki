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

import java.io.ByteArrayInputStream;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.CaManager;
import org.xipki.ca.server.mgmt.api.x509.X509ChangeCrlSignerEntry;
import org.xipki.ca.server.mgmt.api.x509.X509CrlSignerEntry;
import org.xipki.ca.server.mgmt.shell.completer.CrlSignerNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.CrlSignerNamePlusNullCompleter;
import org.xipki.common.util.Base64;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.password.PasswordResolver;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "crlsigner-up",
        description = "update CRL signer")
@Service
public class CrlSignerUpdateCmd extends CaAction {

    @Option(name = "--name", aliases = "-n",
            required = true,
            description = "CRL signer name\n"
                    + "(required)")
    @Completion(CrlSignerNameCompleter.class)
    private String name;

    @Option(name = "--signer-type",
            description = "CRL signer type, use 'CA' to sign the CRL by the CA itself")
    @Completion(CrlSignerNamePlusNullCompleter.class)
    private String signerType;

    @Option(name = "--signer-conf",
            description = "CRL signer configuration")
    private String signerConf;

    @Option(name = "--cert",
            description = "CRL signer's certificate file or 'NULL'")
    @Completion(FilePathCompleter.class)
    private String signerCert;

    @Option(name = "--control",
            description = "CRL control")
    private String crlControl;

    @Reference
    private PasswordResolver passwordResolver;

    protected X509ChangeCrlSignerEntry getCrlSignerChangeEntry() throws Exception {
        String signerCertConf = null;
        if (CaManager.NULL.equalsIgnoreCase(signerCert)) {
            signerCertConf = CaManager.NULL;
        } else if (signerCert != null) {
            byte[] certBytes = IoUtil.read(signerCert);
            X509Util.parseCert(new ByteArrayInputStream(certBytes));
            signerCertConf = Base64.encodeToString(certBytes);
        }

        if (signerConf != null) {
            String tmpSignerType = signerType;
            if (tmpSignerType == null) {
                X509CrlSignerEntry entry = caManager.getCrlSigner(name);
                if (entry == null) {
                    throw new IllegalCmdParamException("please specify the signerType");
                }
                tmpSignerType = entry.type();
            }

            signerConf = ShellUtil.canonicalizeSignerConf(tmpSignerType, signerConf,
                    passwordResolver, securityFactory);
        }

        X509ChangeCrlSignerEntry dbEntry = new X509ChangeCrlSignerEntry(name);
        dbEntry.setSignerType(signerType);
        dbEntry.setSignerConf(signerConf);
        dbEntry.setCrlControl(crlControl);
        dbEntry.setBase64Cert(signerCertConf);
        return dbEntry;
    } // method getCrlSignerChangeEntry

    @Override
    protected Object execute0() throws Exception {
        boolean bo = caManager.changeCrlSigner(getCrlSignerChangeEntry());
        output(bo, "updated", "could not update", "CRL signer " + name);
        return null;
    }

}
