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

package org.xipki.pki.ca.server.mgmt.shell.cert;

import java.io.File;
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;
import org.xipki.pki.ca.server.mgmt.api.x509.CertWithStatusInfo;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-ca", name = "cert-status",
        description = "show certificate status and save the certificate")
@Service
public class CertStatusCmd extends UnRevRmCertCommandSupport {

    @Option(name = "--out", aliases = "-o",
            description = "where to save the certificate")
    @Completion(FilePathCompleter.class)
    private String outputFile;

    @Override
    protected Object doExecute() throws Exception {
        CertWithStatusInfo certInfo = caManager.getCert(caName, getSerialNumber());
        X509Certificate cert = (X509Certificate) certInfo.getCert();

        if (cert == null) {
            System.out.println("certificate unknown");
            return null;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("certificate profile: ").append(certInfo.getCertprofile()).append("\n");
        sb.append("status: ");
        if (certInfo.getRevocationInfo() == null) {
            sb.append("good");
        } else {
            sb.append("revoked with ").append(certInfo.getRevocationInfo());
        }
        println(sb.toString());

        if (outputFile != null) {
            saveVerbose("certificate saved to file", new File(outputFile), cert.getEncoded());
        }
        return null;
    }

}
