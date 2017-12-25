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

package org.xipki.ca.server.mgmt.qa.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.x509.CrlControl;
import org.xipki.ca.server.mgmt.api.x509.X509ChangeCrlSignerEntry;
import org.xipki.ca.server.mgmt.api.x509.X509CrlSignerEntry;
import org.xipki.ca.server.mgmt.shell.CrlSignerUpdateCmd;
import org.xipki.console.karaf.CmdFailure;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "caqa", name = "crlsigner-check",
        description = "check information of CRL signers (QA)")
@Service
public class CrlSignerCheckCmd extends CrlSignerUpdateCmd {

    @Override
    protected Object execute0() throws Exception {
        X509ChangeCrlSignerEntry ey = getCrlSignerChangeEntry();
        String name = ey.name();
        println("checking CRL signer " + name);

        X509CrlSignerEntry cs = caManager.getCrlSigner(name);
        if (cs == null) {
            throw new CmdFailure("CRL signer named '" + name + "' is not configured");
        }

        if (ey.signerType() != null) {
            String ex = ey.signerType();
            String is = cs.type();
            MgmtQaShellUtil.assertEquals("signer type", ex, is);
        }

        if (ey.signerConf() != null) {
            String ex = ey.signerConf();
            String is = cs.conf();
            MgmtQaShellUtil.assertEquals("signer conf", ex, is);
        }

        if (ey.crlControl() != null) {
            CrlControl ex = new CrlControl(ey.crlControl());
            CrlControl is = new CrlControl(cs.crlControl());

            if (!ex.equals(is)) {
                throw new CmdFailure("CRL control: is '" + is.getConf() + "', but expected '"
                        + ex.getConf() + "'");
            }
        }

        if (ey.base64Cert() != null) {
            String ex = ey.base64Cert();
            String is = cs.base64Cert();
            MgmtQaShellUtil.assertEquals("certificate", ex, is);
        }

        println(" checked CRL signer " + name);
        return null;
    } // method execute0

}
