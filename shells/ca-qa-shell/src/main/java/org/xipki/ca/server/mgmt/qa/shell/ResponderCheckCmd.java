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

import java.util.Arrays;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.CaManager;
import org.xipki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.ca.server.mgmt.shell.ResponderUpdateCmd;
import org.xipki.common.util.Base64;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.CmdFailure;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "caqa", name = "responder-check",
        description = "check information of responder (QA)")
@Service
public class ResponderCheckCmd extends ResponderUpdateCmd {

    @Override
    protected Object execute0() throws Exception {
        println("checking responder " + name);

        CmpResponderEntry cr = caManager.getResponder(name);
        if (cr == null) {
            throw new CmdFailure("responder named '" + name + "' is not configured");
        }

        if (CaManager.NULL.equalsIgnoreCase(certFile)) {
            if (cr.base64Cert() != null) {
                throw new CmdFailure("Cert: is configured but expected is none");
            }
        } else if (certFile != null) {
            byte[] ex = IoUtil.read(certFile);
            if (cr.base64Cert() == null) {
                throw new CmdFailure("Cert: is not configured explicitly as expected");
            }
            if (!Arrays.equals(ex, Base64.decode(cr.base64Cert()))) {
                throw new CmdFailure("Cert: the expected one and the actual one differ");
            }
        }

        String signerConf = getSignerConf();
        if (signerConf != null) {
            MgmtQaShellUtil.assertEquals("conf", signerConf, cr.conf());
        }

        println(" checked responder " + name);
        return null;
    }

}
