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

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.password.api.PasswordResolver;
import org.xipki.pki.ca.server.mgmt.api.X509CrlSignerEntry;
import org.xipki.pki.ca.server.mgmt.shell.completer.CrlSignerNameCompleter;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-ca", name = "crlsigner-add",
        description = "add CRL signer")
@Service
public class CrlSignerAddCmd extends CaCommandSupport {

    @Option(name = "--name", aliases = "-n",
            required = true,
            description = "CRL signer name\n"
                    + "(required)")
    private String name;

    @Option(name = "--signer-type",
            required = true,
            description = "CRL signer type, use 'CA' to sign the CRL by the CA itself\n"
                    + "(required)")
    @Completion(CrlSignerNameCompleter.class)
    private String signerType;

    @Option(name = "--signer-conf",
            description = "CRL signer configuration")
    private String signerConf;

    @Option(name = "--cert",
            description = "CRL signer's certificate file")
    @Completion(FilePathCompleter.class)
    private String signerCertFile;

    @Option(name = "--control",
            required = true,
            description = "CRL control\n"
                    + "(required)")
    private String crlControl;

    @Reference
    private PasswordResolver passwordResolver;

    @Override
    protected Object doExecute()
    throws Exception {
        String base64Cert = null;
        if (!"CA".equalsIgnoreCase(signerType)) {
            if (signerCertFile != null) {
                byte[] encodedCert = IoUtil.read(signerCertFile);
                base64Cert = IoUtil.base64Encode(encodedCert, false);
                X509Util.parseCert(encodedCert);
            }

            if (signerConf != null) {
                if ("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType)) {
                    signerConf = ShellUtil.canonicalizeSignerConf(signerType,
                            signerConf, passwordResolver);
                }
            }
        }

        X509CrlSignerEntry entry = new X509CrlSignerEntry(name, signerType, signerConf,
                base64Cert, crlControl);
        boolean b = caManager.addCrlSigner(entry);
        output(b, "added", "could not add", "CRL signer " + name);
        return null;
    }

}
