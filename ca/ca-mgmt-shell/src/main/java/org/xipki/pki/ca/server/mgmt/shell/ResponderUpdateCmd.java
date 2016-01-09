/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
import org.xipki.pki.ca.server.mgmt.api.CAManager;
import org.xipki.pki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.pki.ca.server.mgmt.shell.completer.ResponderNameCompleter;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.console.karaf.completer.SignerTypeCompleter;
import org.xipki.password.api.PasswordResolver;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-ca", name = "responder-up",
        description = "update responder")
@Service
public class ResponderUpdateCmd extends CaCmd {
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

    @Option(name = "--signer-conf",
            description = "conf of the responder signer or 'NULL'")
    private String signerConf;

    @Option(name = "--cert",
            description = "requestor certificate file or 'NULL'")
    @Completion(FilePathCompleter.class)
    protected String certFile;

    @Reference
    protected PasswordResolver passwordResolver;

    protected String getSignerConf()
    throws Exception {
        if (signerConf == null) {
            return signerConf;
        }
        String _signerType = signerType;
        if (_signerType == null) {
            CmpResponderEntry entry = caManager.getCmpResponder(name);
            if (entry == null) {
                throw new IllegalCmdParamException("please specify the signerType");
            }
            _signerType = entry.getType();
        }

        return ShellUtil.canonicalizeSignerConf(_signerType, signerConf, passwordResolver);
    }

    @Override
    protected Object doExecute()
    throws Exception {
        String cert = null;
        if (CAManager.NULL.equalsIgnoreCase(certFile)) {
            cert = CAManager.NULL;
        } else if (certFile != null) {
            byte[] certBytes = IoUtil.read(certFile);
            X509Util.parseCert(new ByteArrayInputStream(certBytes));
            cert = Base64.toBase64String(certBytes);
        }

        boolean b = caManager.changeCmpResponder(name, signerType, getSignerConf(), cert);
        output(b, "updated", "could not update", "CMP responder " + name);
        return null;
    }

}
