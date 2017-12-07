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
public class ResponderAddCmd extends CaCommandSupport {

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
