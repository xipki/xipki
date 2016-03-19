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
import org.xipki.commons.password.api.PasswordResolver;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.server.mgmt.api.CaManager;
import org.xipki.pki.ca.server.mgmt.api.X509ChangeCrlSignerEntry;
import org.xipki.pki.ca.server.mgmt.api.X509CrlSignerEntry;
import org.xipki.pki.ca.server.mgmt.shell.completer.CrlSignerNameCompleter;
import org.xipki.pki.ca.server.mgmt.shell.completer.CrlSignerNamePlusNullCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-ca", name = "crlsigner-up",
        description = "update CRL signer")
@Service
public class CrlSignerUpdateCmd extends CaCommandSupport {

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

    protected X509ChangeCrlSignerEntry getCrlSignerChangeEntry()
    throws Exception {
        String signerCertConf = null;
        if (CaManager.NULL.equalsIgnoreCase(signerCert)) {
            signerCertConf = CaManager.NULL;
        } else if (signerCert != null) {
            byte[] certBytes = IoUtil.read(signerCert);
            X509Util.parseCert(new ByteArrayInputStream(certBytes));
            signerCertConf = Base64.toBase64String(certBytes);
        }

        if (signerConf != null) {
            String tmpSignerType = signerType;
            if (tmpSignerType == null) {
                X509CrlSignerEntry entry = caManager.getCrlSigner(name);
                if (entry == null) {
                    throw new IllegalCmdParamException("please specify the signerType");
                }
                tmpSignerType = entry.getType();
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
    protected Object doExecute()
    throws Exception {
        boolean bo = caManager.changeCrlSigner(getCrlSignerChangeEntry());
        output(bo, "updated", "could not update", "CRL signer " + name);
        return null;
    }

}
