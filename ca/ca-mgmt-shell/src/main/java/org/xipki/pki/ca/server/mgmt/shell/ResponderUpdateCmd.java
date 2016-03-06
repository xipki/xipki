/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.pki.ca.server.mgmt.shell;

import java.io.ByteArrayInputStream;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.util.encoders.Base64;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;
import org.xipki.commons.console.karaf.completer.SignerTypeCompleter;
import org.xipki.commons.password.api.PasswordResolver;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.server.mgmt.api.CaManager;
import org.xipki.pki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.pki.ca.server.mgmt.shell.completer.ResponderNameCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-ca", name = "responder-up",
        description = "update responder")
@Service
public class ResponderUpdateCmd extends CaCommandSupport {

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

    protected String getSignerConf()
    throws Exception {
        if (signerConf == null) {
            return signerConf;
        }
        String tmpSignerType = signerType;
        if (tmpSignerType == null) {
            CmpResponderEntry entry = caManager.getCmpResponder(name);
            if (entry == null) {
                throw new IllegalCmdParamException("please specify the signerType");
            }
            tmpSignerType = entry.getType();
        }

        return ShellUtil.canonicalizeSignerConf(tmpSignerType, signerConf, passwordResolver,
                securityFactory);
    }

    @Override
    protected Object doExecute()
    throws Exception {
        String cert = null;
        if (CaManager.NULL.equalsIgnoreCase(certFile)) {
            cert = CaManager.NULL;
        } else if (certFile != null) {
            byte[] certBytes = IoUtil.read(certFile);
            X509Util.parseCert(new ByteArrayInputStream(certBytes));
            cert = Base64.toBase64String(certBytes);
        }

        boolean bo = caManager.changeCmpResponder(name, signerType, getSignerConf(), cert);
        output(bo, "updated", "could not update", "CMP responder " + name);
        return null;
    }

}
