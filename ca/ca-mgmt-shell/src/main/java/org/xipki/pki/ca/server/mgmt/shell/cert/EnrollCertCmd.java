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
import java.util.Date;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.common.util.DateUtil;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.pki.ca.server.mgmt.api.CaEntry;
import org.xipki.pki.ca.server.mgmt.shell.CaCommandSupport;
import org.xipki.pki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.pki.ca.server.mgmt.shell.completer.ProfileNameCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-ca", name = "enroll-cert",
        description = "enroll certificate")
@Service
public class EnrollCertCmd extends CaCommandSupport {

    @Option(name = "--ca",
            required = true,
            description = "CA name\n"
                    + "(required)")
    @Completion(CaNameCompleter.class)
    private String caName;

    @Option(name = "--csr",
            required = true,
            description = "CSR file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String csrFile;

    @Option(name = "--out", aliases = "-o",
            required = true,
            description = "where to save the certificate\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Option(name = "--profile", aliases = "-p",
            required = true,
            description = "profile name\n"
                    + "(required)")
    @Completion(ProfileNameCompleter.class)
    private String profileName;

    @Option(name = "--not-before",
            description = "notBefore, UTC time of format yyyyMMddHHmmss")
    private String notBeforeS;

    @Option(name = "--not-after",
            description = "notAfter, UTC time of format yyyyMMddHHmmss")
    private String notAfterS;

    @Override
    protected Object execute0() throws Exception {
        CaEntry ca = caManager.getCa(caName);
        if (ca == null) {
            throw new CmdFailure("CA " + caName + " not available");
        }

        Date notBefore = StringUtil.isNotBlank(notBeforeS)
                ? DateUtil.parseUtcTimeyyyyMMddhhmmss(notBeforeS) : null;

        Date notAfter = StringUtil.isNotBlank(notAfterS)
                  ? DateUtil.parseUtcTimeyyyyMMddhhmmss(notAfterS) : null;

        byte[] encodedCsr = IoUtil.read(csrFile);

        X509Certificate cert = caManager.generateCertificate(caName, profileName, encodedCsr,
                notBefore, notAfter);
        saveVerbose("saved certificate to file", new File(outFile), cert.getEncoded());

        return null;
    }

}
