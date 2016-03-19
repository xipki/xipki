/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.server.mgmt.qa.shell;

import java.util.Arrays;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.util.encoders.Base64;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.console.karaf.CmdFailure;
import org.xipki.pki.ca.server.mgmt.api.CaManager;
import org.xipki.pki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.pki.ca.server.mgmt.shell.ResponderUpdateCmd;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-caqa", name = "responder-check",
        description = "check information of responder (QA)")
@Service
public class ResponderCheckCmd extends ResponderUpdateCmd {

    @Override
    protected Object doExecute()
    throws Exception {
        println("checking responder " + name);

        CmpResponderEntry cr = caManager.getCmpResponder(name);
        if (cr == null) {
            throw new CmdFailure("CMP responder named '" + name + "' is not configured");
        }

        if (CaManager.NULL.equalsIgnoreCase(certFile)) {
            if (cr.getBase64Cert() != null) {
                throw new CmdFailure("Cert: is configured but expected is none");
            }
        } else if (certFile != null) {
            byte[] ex = IoUtil.read(certFile);
            if (cr.getBase64Cert() == null) {
                throw new CmdFailure("Cert: is not configured explicitly as expected");
            }
            if (!Arrays.equals(ex, Base64.decode(cr.getBase64Cert()))) {
                throw new CmdFailure("Cert: the expected one and the actual one differ");
            }
        }

        String signerConf = getSignerConf();
        if (signerConf != null) {
            MgmtQaShellUtil.assertEquals("conf", signerConf, cr.getConf());
        }

        println(" checked responder " + name);
        return null;
    }

}
