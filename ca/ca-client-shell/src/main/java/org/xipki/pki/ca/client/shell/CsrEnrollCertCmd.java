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

package org.xipki.pki.ca.client.shell;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.xipki.commons.common.RequestResponseDebug;
import org.xipki.commons.common.util.DateUtil;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.console.karaf.CmdFailure;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;
import org.xipki.pki.ca.client.api.CertOrError;
import org.xipki.pki.ca.client.api.EnrollCertResult;
import org.xipki.pki.ca.client.shell.completer.CaNameCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-cli", name = "csr-enroll",
        description = "enroll certificate via CSR")
@Service
public class CsrEnrollCertCmd extends ClientCommandSupport {

    @Option(name = "--csr",
            required = true,
            description = "CSR file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String csrFile;

    @Option(name = "--profile", aliases = "-p",
            required = true,
            description = "certificate profile\n"
                    + "(required)")
    private String profile;

    @Option(name = "--not-before",
            description = "notBefore, UTC time of format yyyyMMddHHmmss")
    private String notBeforeS;

    @Option(name = "--not-after",
            description = "notAfter, UTC time of format yyyyMMddHHmmss")
    private String notAfterS;

    @Option(name = "--out", aliases = "-o",
            required = true,
            description = "where to save the certificate\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String outputFile;

    @Option(name = "--user",
            description = "username")
    private String user;

    @Option(name = "--ca",
            description = "CA name\n"
                    + "(required if the profile is supported by more than one CA)")
    @Completion(CaNameCompleter.class)
    private String caName;

    @Override
    protected Object doExecute() throws Exception {
        CertificationRequest csr = CertificationRequest.getInstance(IoUtil.read(csrFile));

        Date notBefore = StringUtil.isNotBlank(notBeforeS)
                ? DateUtil.parseUtcTimeyyyyMMddhhmmss(notBeforeS) : null;
        Date notAfter = StringUtil.isNotBlank(notAfterS)
                  ? DateUtil.parseUtcTimeyyyyMMddhhmmss(notAfterS) : null;
        EnrollCertResult result;
        RequestResponseDebug debug = getRequestResponseDebug();
        try {
            result = caClient.requestCert(caName, csr, profile, user, notBefore, notAfter, debug);
        } finally {
            saveRequestResponse(debug);
        }

        X509Certificate cert = null;
        if (result != null) {
            String id = result.getAllIds().iterator().next();
            CertOrError certOrError = result.getCertificateOrError(id);
            cert = (X509Certificate) certOrError.getCertificate();
        }

        if (cert == null) {
            throw new CmdFailure("no certificate received from the server");
        }

        File certFile = new File(outputFile);
        saveVerbose("certificate saved to file", certFile, cert.getEncoded());
        return null;
    }

}
