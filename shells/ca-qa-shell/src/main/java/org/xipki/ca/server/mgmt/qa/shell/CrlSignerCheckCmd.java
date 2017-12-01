/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

@Command(scope = "xipki-caqa", name = "crlsigner-check",
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
